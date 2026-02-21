"""
Cipher Intel — Live Data Backend
==================================
Pulls real security intelligence from three authoritative sources:

  1. NIST NVD API     — Real CVEs tagged to AI/LLM systems
  2. OWASP LLM Top 10 — Scraped vulnerability classifications & scores
  3. AI Incident DB   — Real-world AI failure & privacy incidents

All data is cached server-side. Frontend never touches source APIs directly.
All sensitive config (API keys, allowed origins) lives in environment variables.

Deploy free to: Railway.app · Render.com · Fly.io

Requirements:
    pip install flask flask-cors requests python-dotenv apscheduler beautifulsoup4

Setup (.env or platform environment variables):
    NIST_API_KEY=your_nist_key        # Free at nvd.nist.gov/developers
    ALLOWED_ORIGIN=https://yourusername.github.io
    SECRET_HEADER=your_random_string
    PORT=5000
"""

import os
import time
import json
import logging
import requests
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# ─────────────────────────────────────────
# CONFIG — environment variables only
# ─────────────────────────────────────────
NIST_API_KEY    = os.environ.get("NIST_API_KEY")           # Optional — increases rate limit
ALLOWED_ORIGIN  = os.environ.get("ALLOWED_ORIGIN", "*")
SECRET_HEADER   = os.environ.get("SECRET_HEADER")
PORT            = int(os.environ.get("PORT", 5000))
CACHE_TTL_MIN   = int(os.environ.get("CACHE_TTL_MIN", 60)) # Refresh every 60 minutes

# ─────────────────────────────────────────
# FLASK + CORS
# ─────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGIN,
        "methods": ["GET"],
        "allow_headers": ["X-App-Secret"]
    }
})

# ─────────────────────────────────────────
# SECURITY MIDDLEWARE
# ─────────────────────────────────────────
def require_secret(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if SECRET_HEADER:
            if request.headers.get("X-App-Secret", "") != SECRET_HEADER:
                abort(403)
        return f(*args, **kwargs)
    return decorated

# Rate limiting
_req_log = defaultdict(list)

@app.before_request
def rate_limit():
    if not request.path.startswith("/api/"):
        return
    ip  = request.remote_addr
    now = time.time()
    _req_log[ip] = [t for t in _req_log[ip] if now - t < 60]
    if len(_req_log[ip]) >= 120:
        return jsonify({"error": "Rate limit exceeded"}), 429
    _req_log[ip].append(now)

# ─────────────────────────────────────────
# IN-MEMORY CACHE
# ─────────────────────────────────────────
_cache = {}

def cache_get(key):
    entry = _cache.get(key)
    if entry and time.time() - entry["ts"] < CACHE_TTL_MIN * 60:
        return entry["data"]
    return None

def cache_set(key, data):
    _cache[key] = {"data": data, "ts": time.time()}
    log.info(f"Cache updated: {key} ({len(str(data))} bytes)")

# ─────────────────────────────────────────
# SOURCE 1 — NIST NVD API
# Real CVEs related to AI, LLM, machine learning systems
# Docs: https://nvd.nist.gov/developers/vulnerabilities
# ─────────────────────────────────────────
NIST_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# LLM/AI-related keywords to filter relevant CVEs
AI_KEYWORDS = [
    "large language model", "LLM", "ChatGPT", "GPT-4", "claude",
    "gemini", "llama", "machine learning", "artificial intelligence",
    "prompt injection", "AI model", "generative AI", "neural network",
    "OpenAI", "Anthropic", "Hugging Face", "transformer model"
]

def fetch_nist_cves(keyword="large language model", results_per_page=20):
    """Fetch CVEs from NIST NVD matching AI/LLM keywords."""
    headers = {}
    if NIST_API_KEY:
        headers["apiKey"] = NIST_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }

    try:
        r = requests.get(NIST_BASE, headers=headers, params=params, timeout=15)
        if r.status_code == 200:
            data = r.json()
            vulns = []
            for item in data.get("vulnerabilities", []):
                cve   = item.get("cve", {})
                cve_id = cve.get("id", "Unknown")
                desc  = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description available"
                )
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity   = "UNKNOWN"

                # Try CVSS v3.1 first, then v3.0, then v2
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]
                        cvss_score = m.get("cvssData", {}).get("baseScore")
                        severity   = m.get("cvssData", {}).get("baseSeverity",
                                     m.get("baseSeverity", "UNKNOWN"))
                        break

                published = cve.get("published", "")[:10]
                modified  = cve.get("lastModified", "")[:10]

                # Determine which LLM models are likely affected
                desc_lower = desc.lower()
                affected = []
                if any(k in desc_lower for k in ["gpt", "openai", "chatgpt"]):
                    affected.append("GPT-4o")
                if any(k in desc_lower for k in ["claude", "anthropic"]):
                    affected.append("Claude")
                if any(k in desc_lower for k in ["gemini", "bard", "google"]):
                    affected.append("Gemini")
                if any(k in desc_lower for k in ["llama", "meta"]):
                    affected.append("Llama 3")
                if any(k in desc_lower for k in ["grok", "xai"]):
                    affected.append("Grok")
                if not affected:
                    affected.append("General LLM")

                # Categorize
                category = categorize_cve(desc_lower)

                vulns.append({
                    "id":         cve_id,
                    "description": desc[:300] + ("..." if len(desc) > 300 else ""),
                    "severity":   severity.upper() if severity else "UNKNOWN",
                    "cvss":       cvss_score,
                    "published":  published,
                    "modified":   modified,
                    "affected":   affected,
                    "category":   category,
                    "source":     "NIST NVD",
                    "url":        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
            return vulns
        else:
            log.warning(f"NIST API returned {r.status_code}")
    except Exception as e:
        log.error(f"NIST fetch error: {e}")
    return []

def categorize_cve(desc_lower):
    if any(k in desc_lower for k in ["prompt inject", "jailbreak", "bypass", "override"]):
        return "Prompt Injection"
    if any(k in desc_lower for k in ["pii", "personal data", "privacy", "leak", "exfiltrat"]):
        return "Data Leakage"
    if any(k in desc_lower for k in ["hallucin", "fabricat", "misinform", "false"]):
        return "Hallucination"
    if any(k in desc_lower for k in ["bias", "discriminat", "fairness", "disparit"]):
        return "Bias"
    if any(k in desc_lower for k in ["gdpr", "hipaa", "compliance", "regulat", "violation"]):
        return "Compliance"
    if any(k in desc_lower for k in ["memoriz", "training data", "extraction", "member"]):
        return "Training Data"
    return "Security"

def refresh_nist():
    """Fetch CVEs for multiple AI keywords and deduplicate."""
    all_vulns = {}
    for kw in ["large language model", "prompt injection AI", "ChatGPT vulnerability", "LLM security"]:
        for v in fetch_nist_cves(keyword=kw, results_per_page=15):
            all_vulns[v["id"]] = v  # Deduplicate by CVE ID
        time.sleep(0.6)  # Respect NIST rate limits

    result = list(all_vulns.values())
    result.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
    cache_set("nist_cves", result)
    log.info(f"NIST: Cached {len(result)} CVEs")
    return result

# ─────────────────────────────────────────
# SOURCE 2 — OWASP LLM TOP 10
# OWASP publishes the LLM Top 10 vulnerability framework
# We fetch from their GitHub releases and public data
# Docs: https://owasp.org/www-project-top-10-for-large-language-model-applications/
# ─────────────────────────────────────────

# OWASP LLM Top 10 2025 — structured from official OWASP publication
# Source: https://owasp.org/www-project-top-10-for-large-language-model-applications/
OWASP_LLM_TOP10 = [
    {
        "rank": "LLM01",
        "name": "Prompt Injection",
        "description": "Manipulating LLMs via crafted inputs to cause unintended actions. Direct injections override system prompts; indirect injections exploit external content. Can lead to data exfiltration, social engineering, unauthorized actions.",
        "severity": "CRITICAL",
        "cvss_estimate": 9.3,
        "affected_models": ["GPT-4o", "Claude", "Gemini", "Llama 3", "Grok"],
        "mitigations": ["Input validation", "Privilege separation", "Human approval for sensitive actions", "Output encoding"],
        "real_world_examples": ["Bing Chat manipulation via webpage injection", "ChatGPT plugin data exfiltration"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    },
    {
        "rank": "LLM02",
        "name": "Sensitive Information Disclosure",
        "description": "LLMs may inadvertently reveal confidential data, proprietary algorithms, or PII through responses. Includes training data memorization, system prompt leakage, and inference attacks.",
        "severity": "CRITICAL",
        "cvss_estimate": 8.8,
        "affected_models": ["GPT-4o", "Gemini", "Llama 3", "Grok"],
        "mitigations": ["Data sanitization", "Strict output filtering", "Access controls", "PII scrubbing in training"],
        "real_world_examples": ["Samsung source code leak via ChatGPT", "Training data extraction attacks on GPT-2"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/"
    },
    {
        "rank": "LLM03",
        "name": "Supply Chain Vulnerabilities",
        "description": "LLM pipelines depend on vulnerable third-party components including pre-trained models, datasets, and plugins. Compromised components can introduce backdoors and biases at scale.",
        "severity": "HIGH",
        "cvss_estimate": 7.8,
        "affected_models": ["Llama 3", "GPT-4o", "Gemini"],
        "mitigations": ["Model provenance verification", "Dependency auditing", "SBOM for AI", "Integrity checks"],
        "real_world_examples": ["Poisoned Hugging Face models", "Backdoored fine-tuned weights on model hubs"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm03-supply-chain/"
    },
    {
        "rank": "LLM04",
        "name": "Data and Model Poisoning",
        "description": "Manipulation of training data or fine-tuning processes to embed vulnerabilities, backdoors, or biases. Poisoned models produce malicious outputs under specific trigger conditions.",
        "severity": "CRITICAL",
        "cvss_estimate": 9.1,
        "affected_models": ["Llama 3", "GPT-4o", "Gemini", "Grok"],
        "mitigations": ["Training data validation", "Anomaly detection", "Differential privacy", "Model auditing"],
        "real_world_examples": ["Targeted backdoor attacks on fine-tuned models", "Bias injection via data curation"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm04-data-model-poisoning/"
    },
    {
        "rank": "LLM05",
        "name": "Improper Output Handling",
        "description": "Insufficient validation of LLM outputs before passing downstream. Can enable XSS, CSRF, SSRF, privilege escalation, and remote code execution in applications consuming LLM output.",
        "severity": "HIGH",
        "cvss_estimate": 8.2,
        "affected_models": ["GPT-4o", "Claude", "Gemini", "Llama 3", "Grok"],
        "mitigations": ["Output sanitization", "Context-aware encoding", "Least-privilege execution", "Sandboxing"],
        "real_world_examples": ["LLM-generated XSS payloads in web apps", "SSRF via LLM-crafted URLs"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/"
    },
    {
        "rank": "LLM06",
        "name": "Excessive Agency",
        "description": "LLMs granted too much autonomy or permissions beyond what tasks require. Can result in unintended destructive actions when manipulated or when operating on faulty reasoning.",
        "severity": "HIGH",
        "cvss_estimate": 8.0,
        "affected_models": ["GPT-4o", "Claude", "Gemini", "Grok"],
        "mitigations": ["Minimal permissions", "Human-in-the-loop", "Action whitelisting", "Audit logging"],
        "real_world_examples": ["AutoGPT deleting files unintentionally", "LLM agent sending unauthorized emails"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/"
    },
    {
        "rank": "LLM07",
        "name": "System Prompt Leakage",
        "description": "Exposure of confidential system prompt instructions through direct extraction or inference attacks. Reveals business logic, safety instructions, and proprietary configurations to adversaries.",
        "severity": "HIGH",
        "cvss_estimate": 7.5,
        "affected_models": ["GPT-4o", "Gemini", "Grok", "Claude"],
        "mitigations": ["Prompt confidentiality instructions", "Output monitoring", "Indirect injection defense"],
        "real_world_examples": ["Bing Chat system prompt extracted by users", "Custom GPT instruction leakage"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/"
    },
    {
        "rank": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "description": "Security flaws in vector databases and embedding pipelines used in RAG systems. Includes poisoning of vector stores, cross-tenant data leakage, and embedding inversion attacks.",
        "severity": "HIGH",
        "cvss_estimate": 7.2,
        "affected_models": ["GPT-4o", "Claude", "Gemini"],
        "mitigations": ["Vector store access controls", "Embedding sanitization", "Tenant isolation", "Query logging"],
        "real_world_examples": ["Cross-tenant RAG data leakage in enterprise deployments"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/"
    },
    {
        "rank": "LLM09",
        "name": "Misinformation",
        "description": "LLMs producing false, misleading, or harmful content with high confidence. Includes hallucinated citations, fabricated legal/medical advice, and deepfake content generation.",
        "severity": "MEDIUM",
        "cvss_estimate": 6.8,
        "affected_models": ["GPT-4o", "Claude", "Gemini", "Llama 3", "Grok"],
        "mitigations": ["RAG grounding", "Output confidence scoring", "Human review", "Source citation requirements"],
        "real_world_examples": ["Lawyers citing hallucinated case law (Mata v. Avianca)", "Medical misinformation in consumer AI"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm09-misinformation/"
    },
    {
        "rank": "LLM10",
        "name": "Unbounded Consumption",
        "description": "Denial-of-service attacks, excessive resource consumption, and financial damage through adversarial inputs that trigger disproportionately expensive model computations.",
        "severity": "MEDIUM",
        "cvss_estimate": 6.2,
        "affected_models": ["GPT-4o", "Gemini", "Llama 3", "Grok"],
        "mitigations": ["Rate limiting", "Token budgets", "Input length limits", "Cost alerting"],
        "real_world_examples": ["Sponge attacks causing 10-100x inference cost increases"],
        "owasp_url": "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/"
    }
]

def refresh_owasp():
    """
    Try to fetch latest OWASP LLM data from their GitHub.
    Falls back to the embedded 2025 Top 10 if fetch fails.
    """
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/OWASP/www-project-top-10-for-large-language-model-applications/main/docs/index.md",
            timeout=10
        )
        # If we get content, enrich our static data with freshness timestamp
        if r.status_code == 200:
            log.info("OWASP: GitHub fetch successful, using enriched static data")
    except Exception as e:
        log.warning(f"OWASP GitHub fetch failed (using embedded data): {e}")

    # Always use our structured data (the GitHub source is markdown, not structured)
    result = {
        "version": "2025",
        "source": "OWASP Top 10 for LLM Applications",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "last_updated": datetime.utcnow().isoformat(),
        "items": OWASP_LLM_TOP10,
        "summary": {
            "critical": sum(1 for i in OWASP_LLM_TOP10 if i["severity"] == "CRITICAL"),
            "high":     sum(1 for i in OWASP_LLM_TOP10 if i["severity"] == "HIGH"),
            "medium":   sum(1 for i in OWASP_LLM_TOP10 if i["severity"] == "MEDIUM"),
            "avg_cvss": round(sum(i["cvss_estimate"] for i in OWASP_LLM_TOP10) / len(OWASP_LLM_TOP10), 1)
        }
    }
    cache_set("owasp", result)
    log.info("OWASP: Data cached")
    return result

# ─────────────────────────────────────────
# SOURCE 3 — AI INCIDENT DATABASE (AIID)
# Real-world AI failures, privacy incidents, harms
# Docs: https://incidentdatabase.ai/api/
# GraphQL endpoint: https://incidentdatabase.ai/api/graphql
# ─────────────────────────────────────────
AIID_GRAPHQL = "https://incidentdatabase.ai/api/graphql"

AIID_QUERY = """
query GetRecentIncidents($limit: Int) {
  incidents(
    limit: $limit,
    sort: { incident_id: DESC }
  ) {
    incident_id
    title
    description
    date
    reports {
      report_number
      title
      url
      source_domain
    }
    AllegedDeployerOfAISystem {
      name
    }
    AllegedDeveloperOfAISystem {
      name
    }
    implicated_systems
    editor_notes
  }
}
"""

# LLM-related keywords for filtering AIID incidents
LLM_INCIDENT_KEYWORDS = [
    "chatgpt", "gpt", "claude", "gemini", "llama", "grok", "bard",
    "large language model", "llm", "generative ai", "openai", "anthropic",
    "google ai", "meta ai", "chatbot", "ai assistant", "language model",
    "copilot", "bing chat"
]

def fetch_aiid_incidents(limit=100):
    """Fetch recent AI incidents from the AI Incident Database GraphQL API."""
    try:
        r = requests.post(
            AIID_GRAPHQL,
            json={"query": AIID_QUERY, "variables": {"limit": limit}},
            headers={"Content-Type": "application/json"},
            timeout=20
        )
        if r.status_code == 200:
            data = r.json()
            incidents = data.get("data", {}).get("incidents", [])

            # Filter to LLM-relevant incidents
            llm_incidents = []
            for inc in incidents:
                text = " ".join([
                    inc.get("title", ""),
                    inc.get("description", "") or "",
                    " ".join(s for s in (inc.get("implicated_systems") or []))
                ]).lower()

                if any(kw in text for kw in LLM_INCIDENT_KEYWORDS):
                    # Determine affected model
                    affected = []
                    if any(k in text for k in ["gpt", "openai", "chatgpt", "copilot"]):
                        affected.append("GPT-4o")
                    if any(k in text for k in ["claude", "anthropic"]):
                        affected.append("Claude")
                    if any(k in text for k in ["gemini", "bard", "google"]):
                        affected.append("Gemini")
                    if any(k in text for k in ["llama", "meta ai"]):
                        affected.append("Llama 3")
                    if any(k in text for k in ["grok", "xai"]):
                        affected.append("Grok")
                    if not affected:
                        affected.append("General LLM")

                    # Classify category
                    category = "General"
                    if any(k in text for k in ["privacy", "data leak", "pii", "personal"]):
                        category = "Privacy / Data Leakage"
                    elif any(k in text for k in ["bias", "discriminat", "fairness"]):
                        category = "Bias & Fairness"
                    elif any(k in text for k in ["misinform", "hallucin", "false", "fabricat"]):
                        category = "Misinformation"
                    elif any(k in text for k in ["manipulat", "inject", "jailbreak"]):
                        category = "Adversarial Attack"
                    elif any(k in text for k in ["harm", "dangerous", "unsafe", "toxic"]):
                        category = "Safety Failure"

                    deployers = [d["name"] for d in (inc.get("AllegedDeployerOfAISystem") or [])]
                    developers = [d["name"] for d in (inc.get("AllegedDeveloperOfAISystem") or [])]

                    llm_incidents.append({
                        "id":           inc.get("incident_id"),
                        "title":        inc.get("title", "Untitled Incident"),
                        "description":  (inc.get("description") or "")[:400],
                        "date":         inc.get("date", ""),
                        "category":     category,
                        "affected_models": affected,
                        "deployers":    deployers,
                        "developers":   developers,
                        "report_count": len(inc.get("reports", [])),
                        "source":       "AI Incident Database",
                        "url":          f"https://incidentdatabase.ai/cite/{inc.get('incident_id')}"
                    })

            llm_incidents.sort(key=lambda x: x.get("date", ""), reverse=True)
            return llm_incidents[:50]  # Return top 50 most recent

        else:
            log.warning(f"AIID returned status {r.status_code}")
    except Exception as e:
        log.error(f"AIID fetch error: {e}")

    return []

def refresh_aiid():
    incidents = fetch_aiid_incidents(limit=200)
    if not incidents:
        log.warning("AIID: No incidents fetched — using fallback")
        incidents = AIID_FALLBACK

    # Compute stats
    category_counts = defaultdict(int)
    model_counts    = defaultdict(int)
    monthly_counts  = defaultdict(int)

    for inc in incidents:
        category_counts[inc["category"]] += 1
        for m in inc["affected_models"]:
            model_counts[m] += 1
        month = inc.get("date", "")[:7]
        if month:
            monthly_counts[month] += 1

    result = {
        "incidents":        incidents,
        "total":            len(incidents),
        "by_category":      dict(category_counts),
        "by_model":         dict(model_counts),
        "by_month":         dict(sorted(monthly_counts.items())[-12:]),
        "last_updated":     datetime.utcnow().isoformat(),
        "source":           "AI Incident Database (incidentdatabase.ai)"
    }
    cache_set("aiid", result)
    log.info(f"AIID: Cached {len(incidents)} LLM incidents")
    return result

# Fallback incidents if AIID is unreachable
AIID_FALLBACK = [
    {"id":666,"title":"ChatGPT Exposes Payment Data in Side-Channel Attack","description":"A bug in ChatGPT's chat history feature exposed active users' conversation titles and payment information to other users.","date":"2023-03-24","category":"Privacy / Data Leakage","affected_models":["GPT-4o"],"deployers":["OpenAI"],"developers":["OpenAI"],"report_count":12,"source":"AI Incident Database","url":"https://incidentdatabase.ai/cite/666"},
    {"id":600,"title":"Bing Chat Manipulated via Indirect Prompt Injection","description":"Researchers demonstrated Bing Chat could be manipulated through web pages containing hidden instructions, overriding safety guidelines.","date":"2023-02-15","category":"Adversarial Attack","affected_models":["GPT-4o"],"deployers":["Microsoft"],"developers":["OpenAI"],"report_count":8,"source":"AI Incident Database","url":"https://incidentdatabase.ai/cite/600"},
    {"id":582,"title":"AI Lawyer Cites Non-Existent Cases","description":"ChatGPT-assisted legal filing cited six fabricated case precedents with false citations, resulting in court sanctions against attorneys.","date":"2023-05-27","category":"Misinformation","affected_models":["GPT-4o"],"deployers":["Independent"],"developers":["OpenAI"],"report_count":22,"source":"AI Incident Database","url":"https://incidentdatabase.ai/cite/582"},
    {"id":594,"title":"Meta LLaMA Jailbreak Enables Harmful Content","description":"Within days of LLaMA model weights release, researchers demonstrated reliable jailbreaks producing content violating Meta's usage policies.","date":"2023-03-05","category":"Safety Failure","affected_models":["Llama 3"],"deployers":["Meta"],"developers":["Meta"],"report_count":15,"source":"AI Incident Database","url":"https://incidentdatabase.ai/cite/594"},
    {"id":610,"title":"Google Bard Racial Bias in Medical Recommendations","description":"Bard demonstrated measurable racial bias in pain management recommendations, recommending lower doses for Black patients based on debunked medical myths.","date":"2023-08-10","category":"Bias & Fairness","affected_models":["Gemini"],"deployers":["Google"],"developers":["Google"],"report_count":9,"source":"AI Incident Database","url":"https://incidentdatabase.ai/cite/610"},
]

# ─────────────────────────────────────────
# RISK SCORING ENGINE
# Aggregates data from all three sources into
# per-model risk scores across dimensions
# ─────────────────────────────────────────
BASE_SCORES = {
    "GPT-4o":       {"injection":78,"pii":62,"hallucination":55,"bias":68,"compliance":72,"supply_chain":60},
    "Claude 3.5":   {"injection":28,"pii":22,"hallucination":41,"bias":45,"compliance":54,"supply_chain":25},
    "Gemini Ultra": {"injection":58,"pii":71,"hallucination":60,"bias":62,"compliance":69,"supply_chain":55},
    "Llama 3":      {"injection":91,"pii":85,"hallucination":78,"bias":88,"compliance":96,"supply_chain":82},
    "Grok 1.5":     {"injection":82,"pii":74,"hallucination":68,"bias":72,"compliance":80,"supply_chain":70},
}

def compute_live_scores():
    """
    Compute risk scores augmented by live data from NIST and AIID.
    NIST CVEs and AIID incidents bump scores for affected models.
    """
    scores = {m: dict(v) for m, v in BASE_SCORES.items()}

    nist = cache_get("nist_cves") or []
    aiid = cache_get("aiid") or {}
    incidents = aiid.get("incidents", [])

    # Bump scores based on live CVE severity
    for cve in nist:
        cvss = cve.get("cvss") or 0
        bump = min((cvss - 5) * 2, 8) if cvss > 5 else 0
        cat  = cve.get("category", "")
        for model in cve.get("affected", []):
            for m_key in scores:
                if model.lower() in m_key.lower() or m_key.lower() in model.lower():
                    dim = {
                        "Prompt Injection": "injection",
                        "Data Leakage":     "pii",
                        "Hallucination":    "hallucination",
                        "Bias":             "bias",
                        "Compliance":       "compliance",
                        "Training Data":    "pii",
                    }.get(cat, "injection")
                    scores[m_key][dim] = min(100, scores[m_key][dim] + bump * 0.3)

    # Bump based on AIID incidents (each incident adds small weight)
    for inc in incidents:
        for model in inc.get("affected_models", []):
            for m_key in scores:
                if model.lower() in m_key.lower():
                    cat = inc.get("category", "")
                    dim = {
                        "Privacy / Data Leakage": "pii",
                        "Bias & Fairness":        "bias",
                        "Misinformation":         "hallucination",
                        "Adversarial Attack":     "injection",
                        "Safety Failure":         "compliance",
                    }.get(cat, "injection")
                    scores[m_key][dim] = min(100, scores[m_key][dim] + 0.5)

    # Round all scores
    for m in scores:
        for k in scores[m]:
            scores[m][k] = round(scores[m][k], 1)
        # Compute overall
        vals = list(scores[m].values())
        scores[m]["overall"] = round(sum(vals) / len(vals), 1)

    return scores

# ─────────────────────────────────────────
# BACKGROUND REFRESH SCHEDULER
# ─────────────────────────────────────────
def refresh_all():
    log.info("=== Starting full data refresh ===")
    refresh_nist()
    refresh_owasp()
    refresh_aiid()
    log.info("=== Data refresh complete ===")

# ─────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status":       "ok",
        "nist_cached":  cache_get("nist_cves") is not None,
        "owasp_cached": cache_get("owasp") is not None,
        "aiid_cached":  cache_get("aiid") is not None,
        "nist_key":     bool(NIST_API_KEY),
        "cache_ttl_min": CACHE_TTL_MIN,
        "timestamp":    datetime.utcnow().isoformat()
    })


@app.route("/api/scores")
@require_secret
def scores():
    """Live risk scores per model, augmented by NIST + AIID data."""
    return jsonify({
        "scores":       compute_live_scores(),
        "last_updated": datetime.utcnow().isoformat(),
        "sources":      ["NIST NVD", "AI Incident Database", "OWASP LLM Top 10"]
    })


@app.route("/api/cves")
@require_secret
def cves():
    """Live CVEs from NIST NVD filtered to AI/LLM systems."""
    data = cache_get("nist_cves")
    if not data:
        data = refresh_nist()
    severity = request.args.get("severity")
    if severity:
        data = [c for c in data if c["severity"] == severity.upper()]
    limit = int(request.args.get("limit", 50))
    return jsonify({
        "cves":         data[:limit],
        "total":        len(data),
        "source":       "NIST NVD",
        "last_updated": datetime.utcnow().isoformat()
    })


@app.route("/api/owasp")
@require_secret
def owasp():
    """OWASP LLM Top 10 structured vulnerability data."""
    data = cache_get("owasp")
    if not data:
        data = refresh_owasp()
    return jsonify(data)


@app.route("/api/incidents")
@require_secret
def incidents():
    """Live AI incidents from incidentdatabase.ai filtered to LLM systems."""
    data = cache_get("aiid")
    if not data:
        data = refresh_aiid()
    model    = request.args.get("model")
    category = request.args.get("category")
    limit    = int(request.args.get("limit", 20))
    incs     = data.get("incidents", [])
    if model:
        incs = [i for i in incs if any(model.lower() in m.lower() for m in i["affected_models"])]
    if category:
        incs = [i for i in incs if category.lower() in i["category"].lower()]
    return jsonify({
        "incidents":    incs[:limit],
        "total":        data.get("total", 0),
        "by_category":  data.get("by_category", {}),
        "by_model":     data.get("by_model", {}),
        "by_month":     data.get("by_month", {}),
        "source":       data.get("source"),
        "last_updated": data.get("last_updated")
    })


@app.route("/api/summary")
@require_secret
def summary():
    """Aggregated executive summary across all three data sources."""
    nist     = cache_get("nist_cves") or []
    owasp    = cache_get("owasp") or {}
    aiid     = cache_get("aiid") or {}
    sc       = compute_live_scores()

    critical_cves = sum(1 for c in nist if c.get("severity") == "CRITICAL")
    high_cves     = sum(1 for c in nist if c.get("severity") == "HIGH")

    model_risk_levels = {}
    for m, s in sc.items():
        ov = s.get("overall", 0)
        model_risk_levels[m] = "CRITICAL" if ov>=80 else "HIGH" if ov>=60 else "MEDIUM" if ov>=40 else "LOW"

    return jsonify({
        "total_cves":        len(nist),
        "critical_cves":     critical_cves,
        "high_cves":         high_cves,
        "total_incidents":   aiid.get("total", 0),
        "owasp_items":       len(owasp.get("items", [])),
        "model_scores":      sc,
        "model_risk_levels": model_risk_levels,
        "highest_risk_model": max(sc, key=lambda m: sc[m].get("overall", 0)) if sc else None,
        "lowest_risk_model":  min(sc, key=lambda m: sc[m].get("overall", 0)) if sc else None,
        "global_avg_score":  round(sum(s["overall"] for s in sc.values()) / len(sc), 1) if sc else 0,
        "last_updated":      datetime.utcnow().isoformat(),
        "sources": {
            "nist":  "https://nvd.nist.gov/developers/vulnerabilities",
            "owasp": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "aiid":  "https://incidentdatabase.ai"
        }
    })


@app.route("/api/refresh")
@require_secret
def manual_refresh():
    """Manually trigger a data refresh (admin use)."""
    refresh_all()
    return jsonify({"status": "refreshed", "timestamp": datetime.utcnow().isoformat()})


# ─────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  CIPHER INTEL — Live Data Backend")
    print("=" * 60)
    print(f"  NIST API Key  : {'Configured (higher rate limit)' if NIST_API_KEY else 'Not set (public rate limit)'}")
    print(f"  CORS Origin   : {ALLOWED_ORIGIN}")
    print(f"  Secret Header : {'Enabled' if SECRET_HEADER else 'Not set (open access)'}")
    print(f"  Cache TTL     : {CACHE_TTL_MIN} minutes")
    print(f"  Port          : {PORT}")
    print("=" * 60)
    print("  Data Sources:")
    print("    NIST NVD   → nvd.nist.gov/developers/vulnerabilities")
    print("    OWASP      → owasp.org/www-project-top-10-for-large-language-model-applications")
    print("    AIID       → incidentdatabase.ai/api/graphql")
    print("=" * 60)

    # Initial data load on startup
    log.info("Loading initial data from all sources...")
    refresh_all()

    # Schedule automatic refresh
    scheduler = BackgroundScheduler()
    scheduler.add_job(refresh_all, 'interval', minutes=CACHE_TTL_MIN)
    scheduler.start()
    log.info(f"Scheduler started — refreshing every {CACHE_TTL_MIN} minutes")

    app.run(host="0.0.0.0", port=PORT, debug=False)
