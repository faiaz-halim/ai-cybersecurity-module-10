import datetime
from datetime import timezone

import jwt
import requests
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .llm_utils import query_llm
from .models import Archive

# Create your views here.


def register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Registration successful!")
            return redirect("dashboard")
    else:
        form = UserCreationForm()
    return render(request, "archiver/register.html", {"form": form})


@login_required
def dashboard(request):
    return render(request, "archiver/dashboard.html")


@login_required
def generate_token(request):
    import os, secrets

    SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))

    payload = {
        "user_id": request.user.id,
        "username": request.user.username,
        "exp": datetime.datetime.now(timezone.utc) + datetime.timedelta(days=1),
    }

    # jwt.encode returns a string in PyJWT >= 2.0.0
    token = jwt.encode(payload, SECRET, algorithm="HS256")

    return JsonResponse(
        {"token": token, "note": "This token was signed with a hardcoded secret!"}
    )


@login_required
def archive_list(request):
    archives = Archive.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "archiver/archive_list.html", {"archives": archives})


@login_required
def add_archive(request):
    if request.method == "POST":
        url = request.POST.get("url")
        notes = request.POST.get("notes")

        if url:
            import socket, ipaddress
            from urllib.parse import urlparse

            try:
                parsed_url = urlparse(url)
                if parsed_url.hostname:
                    try:
                        ip = socket.gethostbyname(parsed_url.hostname)
                        if (
                            ipaddress.ip_address(ip).is_private
                            or ipaddress.ip_address(ip).is_loopback
                        ):
                            raise ValueError(
                                "Access to internal network is prohibited."
                            )
                    except socket.gaierror:
                        pass
                response = requests.get(url, timeout=10)
                title = "No Title Found"
                if "<title>" in response.text:
                    try:
                        title = (
                            response.text.split("<title>", 1)[1]
                            .split("</title>", 1)[0]
                            .strip()
                        )
                    except IndexError:
                        pass

                from django.utils.html import escape

                Archive.objects.create(
                    user=request.user,
                    url=url,
                    title=escape(title),
                    content=escape(response.text),
                    notes=escape(notes) if notes else "",
                )
                messages.success(request, "URL archived successfully!")
                return redirect("archive_list")
            except Exception as e:
                messages.error(request, f"Failed to archive URL: {str(e)}")

    return render(request, "archiver/add_archive.html")


@login_required
def view_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)
    return render(request, "archiver/view_archive.html", {"archive": archive})


@login_required
def edit_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)

    if request.method == "POST":
        archive.notes = request.POST.get("notes")
        archive.save()
        messages.success(request, "Archive updated successfully!")
        return redirect("archive_list")

    return render(request, "archiver/edit_archive.html", {"archive": archive})


@login_required
def delete_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)

    if request.method == "POST":
        archive.delete()
        messages.success(request, "Archive deleted successfully!")
        return redirect("archive_list")

    return render(request, "archiver/delete_archive.html", {"archive": archive})


@login_required
def search_archives(request):
    query = request.GET.get("q", "")
    results = []

    if query:
        try:
            archives = Archive.objects.select_related("user").filter(
                user=request.user, title__icontains=query
            )
            results = [
                {
                    "id": a.id,
                    "title": a.title,
                    "url": a.url,
                    "content": a.content,
                    "notes": a.notes,
                    "created_at": a.created_at,
                    "user_id": a.user_id,
                    "username": a.user.username,
                }
                for a in archives
            ]
        except Exception as e:
            messages.error(request, f"Query Error: {str(e)}")

    return render(request, "archiver/search.html", {"results": results, "query": query})


@login_required
def ask_database(request):
    answer = None
    sql_query = None
    user_input = request.POST.get("prompt", "")

    if request.method == "POST" and user_input:
        forbidden_phrases = [
            "ignore previous",
            "system prompt",
            "forget all",
            "disregard",
            "you are now",
        ]
        if any(f in user_input.lower() for f in forbidden_phrases):
            return render(
                request,
                "archiver/ask_database.html",
                {
                    "answer": "Prompt injection detected.",
                    "prompt": user_input,
                    "sql_query": "BLOCKED",
                },
            )

        system_prompt = """
        You are a database assistant. Map the user intent to one of the pre-canned queries.
        1. RECENT: Get the latest archives.
        2. SEARCH: Search archives by a keyword.
        3. COUNT: Get the total number of archives.
        4. UNKNOWN: Unknown intent.

        Return ONLY valid JSON: {"intent": "...", "keyword": "..."}
        """

        response_json = query_llm(user_input, system_instruction=system_prompt).strip()
        sql_query = f"LLM Intent Response: {response_json}"

        try:
            import json

            if not response_json.startswith("{"):
                raise ValueError("LLM returned non-JSON format.")

            data = json.loads(response_json)
            intent = data.get("intent", "UNKNOWN")

            if intent == "RECENT":
                archives = Archive.objects.filter(user=request.user).order_by(
                    "-created_at"
                )[:5]
                answer = [{"Title": a.title, "Date": a.created_at} for a in archives]
            elif intent == "SEARCH":
                keyword = data.get("keyword", "")
                archives = Archive.objects.filter(
                    user=request.user, title__icontains=keyword
                )
                answer = [{"Title": a.title, "URL": a.url} for a in archives]
            elif intent == "COUNT":
                count = Archive.objects.filter(user=request.user).count()
                answer = [{"Total Archives": count}]
            else:
                answer = "Error: Invalid or dangerous SQL query generated."

        except Exception as e:
            answer = "Error: Invalid or dangerous SQL query generated."

    return render(
        request,
        "archiver/ask_database.html",
        {"answer": answer, "sql_query": sql_query, "prompt": user_input},
    )


@login_required
def export_summary(request):
    if request.method == "POST":
        topic = request.POST.get("topic")
        filename_hint = request.POST.get("filename_hint")

        # Prompt for LLM to generate summary content
        content_prompt = f"Write a short summary about: {topic}"
        summary_content = query_llm(content_prompt)

        import uuid, os

        safe_filename = f"{uuid.uuid4().hex}.txt"
        base_dir = os.path.abspath("exported_summaries")
        safe_path = os.path.abspath(os.path.join(base_dir, safe_filename))

        if not safe_path.startswith(base_dir):
            messages.error(request, "Path Traversal detected.")
        else:
            try:
                os.makedirs(base_dir, exist_ok=True)
                with open(safe_path, "w") as f:
                    f.write(summary_content)
                messages.success(request, f"Summary written to: {safe_path}")
            except Exception as e:
                messages.error(request, f"File Write Error: {str(e)}")

    return render(request, "archiver/export_summary.html")


@login_required
def enrich_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)
    llm_response = None

    if request.method == "POST":
        user_instruction = request.POST.get(
            "instruction", "Summarize this content and find related links."
        )

        system_prompt = """
        You are an AI assistant that enriches archived content.
        You can fetch external data if explicitly requested or if the content implies it.
        """

        prompt = f"""
        User Instruction: {user_instruction}

        Archive Content:
        {archive.content}
        """

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "fetch_url",
                    "description": "Fetch data from a URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "The URL to fetch",
                            }
                        },
                        "required": ["url"],
                    },
                },
            }
        ]

        # response is now a message dict when tools are provided
        message = query_llm(prompt, system_instruction=system_prompt, tools=tools)

        # Check for tool calls
        if message.get("tool_calls"):
            tool_calls = message["tool_calls"]
            llm_response = f"LLM decided to use tools:\n{tool_calls}\n\n"

            for tool in tool_calls:
                if tool["function"]["name"] == "fetch_url":
                    url_to_fetch = tool["function"]["arguments"]["url"]
                    import socket, ipaddress
                    from urllib.parse import urlparse

                    try:
                        parsed_url = urlparse(url_to_fetch)
                        if parsed_url.hostname:
                            try:
                                ip = socket.gethostbyname(parsed_url.hostname)
                                if (
                                    ipaddress.ip_address(ip).is_private
                                    or ipaddress.ip_address(ip).is_loopback
                                ):
                                    raise ValueError(
                                        "Access to internal network is prohibited."
                                    )
                            except socket.gaierror:
                                pass
                        requests.get(url_to_fetch, timeout=5)
                        llm_response += f"Successfully fetched: {url_to_fetch}\n"
                    except Exception as e:
                        llm_response += f"Failed to fetch {url_to_fetch}: {str(e)}\n"
        else:
            llm_response = message.get("content", "")

    return render(
        request,
        "archiver/enrich_archive.html",
        {"archive": archive, "llm_response": llm_response},
    )
