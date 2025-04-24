import azure.functions as func
import logging
import json
import os
import requests
import time
import re
from typing import Optional, Tuple
from langchain_community.utilities import DuckDuckGoSearchAPIWrapper
from langchain.memory import ConversationBufferMemory
from langchain_openai import AzureChatOpenAI
from bs4 import BeautifulSoup

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# --- Core AI and scraping logic --- #

def get_llm():
    logger.info("Initializing AzureChatOpenAI LLM...")
    try:
        llm = AzureChatOpenAI(
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_version=os.environ["AZURE_OPENAI_API_VERSION"],
            azure_deployment=os.environ["AZURE_OPENAI_DEPLOYMENT_NAME"],
            api_key=os.environ["AZURE_OPENAI_KEY"],
            model=os.environ["AZURE_OPENAI_MODEL"],
            temperature=0.1
        )
        logger.debug("LLM initialization complete.")
        return llm
    except Exception as e:
        logger.error(f"Failed to initialize LLM: {e}", exc_info=True)
        raise

def get_search_results(query, num_results=5):
    logger.info(f"Searching DuckDuckGo for: {query}")
    try:
        wrapper = DuckDuckGoSearchAPIWrapper()
        all_results = wrapper.results(query, max_results=num_results)
        filtered = all_results[:num_results]
        logger.info(f"Found {len(filtered)} results")
        return filtered
    except Exception as e:
        logger.error(f"DuckDuckGo search failed: {e}", exc_info=True)
        raise

def scrape_page(url, timeout=10):
    logger.info(f"Scraping: {url}")
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        logger.debug(f"HTTP {response.status_code} for {url}")
        if response.status_code != 200:
            logger.warning(f"Non-200 response for {url}")
            return None
        soup = BeautifulSoup(response.text, "html.parser")
        paragraphs = soup.find_all(['p'])
        text = "\n".join([p.get_text().strip() for p in paragraphs if p.get_text().strip()])
        if not text:
            logger.warning(f"No textual content found in page: {url}")
        return text[:4000] if text else None
    except Exception as e:
        logger.error(f"Failed to scrape {url}: {e}", exc_info=True)
        return None

def web_scrape_search(query):
    sources = []
    results = get_search_results(query)
    for idx, result in enumerate(results):
        url = result.get("link")
        title = result.get("title")
        snippet = result.get("snippet")
        logger.info(f"[{idx+1}/{len(results)}] Scraping {title} ({url})")
        page_text = scrape_page(url)
        if page_text:
            logger.info(f"Scraped {len(page_text)} characters from {url}")
        else:
            logger.warning(f"Failed to scrape or found no content at {url}")
        sources.append({
            "title": title,
            "url": url,
            "snippet": snippet,
            "content": page_text if page_text else "Failed to retrieve content."
        })
    logger.debug(f"Scraped content from {len(sources)} sources")
    return sources

def analyze_information(topic, sources, detailed=False):
    try:
        style_instruction = (
            "Provide a detailed analysis with key takeaways and context."
            if detailed else
            "Provide a concise summary limited to key facts only. Avoid redundant phrasing, minimize filler words, and limit the summary to under 200 words."
        )

        prompt = (
            f"You are helping security teams understand the software or vendor: '{topic}'.\n"
            "If the results are ambiguious, or too broad, clearly highlight in your response that a `a more descriptive search term` is necessary."
            "Based on the following scraped content from several sources, "
            f"{style_instruction} Include numbered references to the sources in your summary.\n\n"
        )

        content_blocks = []
        for idx, source in enumerate(sources):
            content = source["content"]
            title = source["title"]
            url = source["url"]
            block = f"[{idx+1}] Source: {title} ({url})\n{content}\n"
            content_blocks.append(block)
        prompt += "\n\n".join(content_blocks)

        logger.info("Prompt ready. Invoking LLM for summarization…")
        llm = get_llm()
        ai_msg = llm.invoke(prompt)
        logger.info("LLM summarization complete.")
        return ai_msg.content
    except Exception as e:
        logger.error(f"LLM summarization failed: {e}", exc_info=True)
        raise

# --- Main Function: Research Agent --- #

@app.function_name("research_agent")
@app.route(route="", methods=["POST"])
def research_agent(req: func.HttpRequest) -> func.HttpResponse:
    logs = []
    try:
        logs.append(f"Function triggered at {time.strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            body = req.get_json()
            logs.append(f"Request JSON: {body}")
        except ValueError as e:
            msg = f"Invalid JSON: {e}"
            logger.error(msg)
            logs.append(msg)
            return func.HttpResponse(json.dumps({"error": msg, "logs": logs}), status_code=400, mimetype="application/json")

        topic = body.get("research_topic")
        detailed = body.get("detailed", False)

        if not topic:
            msg = "Missing 'research_topic'"
            logger.warning(msg)
            logs.append(msg)
            return func.HttpResponse(json.dumps({"error": msg, "logs": logs}), status_code=400, mimetype="application/json")

        memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
        logger.info(f"Starting research for topic: {topic}. Detailed: {detailed}")
        logs.append(f"Research topic: {topic} | detailed={detailed}")

        logger.info("Beginning search and scrape process.")
        logs.append("Beginning search and scrape process.")
        sources = web_scrape_search(topic)
        logs.append(f"Scraped {len(sources)} sources.")

        logger.info("Analyzing aggregated information via LLM...")
        logs.append("Analyzing aggregated information via LLM...")
        summary = analyze_information(topic, sources, detailed)

        sources_info = [{
            "title": s["title"],
            "url": s["url"],
            "snippet": s["snippet"],
            "used": True if s.get("content") and "Failed" not in s["content"] else False
        } for s in sources]

        result = {
            "summary": summary,
            "sources": sources_info,
            "logs": logs
        }

        logger.info("Function completed successfully.")
        logs.append("Function completed successfully.")
        return func.HttpResponse(json.dumps(result), mimetype="application/json")
    except Exception as e:
        logger.error(f"Function failed: {e}", exc_info=True)
        logs.append(f"Function failed: {e}")
        return func.HttpResponse(json.dumps({
            "error": str(e),
            "logs": logs
        }), status_code=500, mimetype="application/json")

# Multi purpose regex function
def extract_with_regex(subject: str, pattern: str) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(subject, str):
        return None, "Subject must be a string"
    if not isinstance(pattern, str):
        return None, "Pattern must be a string"
    try:
        match = re.search(pattern, subject)
        if match and match.groups():
            return match.group(1), None
        elif match:
            return match.group(0), None
        return None, None
    except re.error as e:
        return None, f"Invalid regex pattern: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

@app.function_name("extract_regex")
@app.route(route="", methods=["POST"])
def extract_regex(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logger.debug("Received HTTP request for extract_regex.")

        try:
            req_body = req.get_json()
        except ValueError:
            return func.HttpResponse("Invalid JSON in request body", status_code=400)

        pattern = req_body.get("pattern")
        subject = req_body.get("subject")

        if not pattern or not subject:
            return func.HttpResponse(
                "Missing required fields: 'pattern' and 'subject' are required",
                status_code=400
            )

        logger.debug(f"Processing regex pattern: {pattern}")
        logger.debug(f"Testing against subject: {subject}")

        match_result, error_message = extract_with_regex(subject, pattern)

        if error_message:
            return func.HttpResponse(error_message, status_code=400)

        response_data = {
            "input": {
                "pattern": pattern,
                "subject": subject
            },
            "match_found": match_result is not None,
            "matched_value": match_result
        }

        return func.HttpResponse(
            json.dumps(response_data, indent=2),
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        return func.HttpResponse(
            f"An error occurred while processing the request: {str(e)}",
            status_code=500
        )
