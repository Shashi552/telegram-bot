from __future__ import annotations
import os
import json
import requests
import logging
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Config - use environment variables where appropriate
# Note: workflow sets TELEGRAM_TOKEN in the Run step env, so we read that name here.
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
BASE_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}" if TELEGRAM_TOKEN else ""
CVE_FEED = os.environ.get("CVE_FEED", "https://cve.circl.lu/api/last")
LAST_SEEN_FILE = os.environ.get("LAST_SEEN_FILE", "last_seen.json")
SUBSCRIBERS_FILE = os.environ.get("SUBSCRIBERS_FILE", "subscribers.json")

# --- Utilities ---
def load_json(path: str, default: Any) -> Any:
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception as e:
        logging.warning("Failed to load %s: %s", path, e)
    return default

def save_json(path: str, data: Any) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error("Failed to write %s: %s", path, e)

def extract_cve_id(cve: Dict[str, Any]) -> Optional[str]:
    if not isinstance(cve, dict):
        return None
    for key in ("id", "ID"):
        if key in cve and isinstance(cve[key], str):
            return cve[key]
    nested = cve.get("cve", {})
    if isinstance(nested, dict):
        if "id" in nested and isinstance(nested["id"], str):
            return nested["id"]
        meta = nested.get("CVE_data_meta", {})
        if isinstance(meta, dict):
            cid = meta.get("ID") or meta.get("id")
            if isinstance(cid, str):
                return cid
    return None

def ref_to_str(ref: Any) -> str:
    """Normalize reference entry into a printable string."""
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        for k in ("url", "href", "link"):
            v = ref.get(k)
            if isinstance(v, str):
                return v
        for k in ("name", "title", "text"):
            v = ref.get(k)
            if isinstance(v, str):
                return v
        for v in ref.values():
            if isinstance(v, str) and v.startswith("http"):
                return v
        try:
            return json.dumps(ref, ensure_ascii=False)
        except Exception:
            return str(ref)
    return str(ref)

# --- TELEGRAM HELPERS ---
def send_message(chat_id: int, text: str) -> None:
    if not TELEGRAM_TOKEN:
        logging.error("TELEGRAM_TOKEN not set; cannot send messages.")
        return
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    try:
        resp = requests.post(f"{BASE_URL}/sendMessage", json=payload, timeout=10)
        if resp.status_code != 200:
            logging.error("Failed to send message to %s: %s %s", chat_id, resp.status_code, resp.text)
    except Exception as e:
        logging.error("Error sending message to %s: %s", chat_id, e)

def get_updates(offset: Optional[int] = None) -> List[Dict[str, Any]]:
    if not TELEGRAM_TOKEN:
        return []
    params = {"offset": offset, "timeout": 10}
    try:
        resp = requests.get(f"{BASE_URL}/getUpdates", params=params, timeout=20)
        data = resp.json()
        return data.get("result", [])
    except Exception as e:
        logging.warning("get_updates error: %s", e)
    return []

# --- HANDLE NEW SUBSCRIBERS ---
def handle_start_commands(subscribers: List[int]) -> List[int]:
    logging.info("Checking for /start commands...")
    last_update_id = None
    updates = get_updates()
    for update in updates:
        last_update_id = update.get("update_id")
        message = update.get("message", {})
        text = message.get("text", "")
        chat_id = message.get("chat", {}).get("id")
        if text == "/start" and chat_id and chat_id not in subscribers:
            subscribers.append(chat_id)
            logging.info("New subscriber: %s", chat_id)
            send_message(chat_id, "✅ You have been subscribed to CVE alerts! You'll get new vulnerabilities every 2 hours.")
    if last_update_id:
        try:
            requests.get(f"{BASE_URL}/getUpdates", params={"offset": last_update_id + 1}, timeout=5)
        except Exception:
            pass
    return subscribers

# --- FETCH & SEND CVES ---
def fetch_latest_cves() -> List[Dict[str, Any]]:
    try:
        resp = requests.get(CVE_FEED, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for k in ("results", "items", "cves"):
                    if k in data and isinstance(data[k], list):
                        return data[k]
    except Exception as e:
        logging.error("Failed to fetch CVE feed: %s", e)
    return []

def format_cve_message(cve: Dict[str, Any]) -> str:
    cve_id = extract_cve_id(cve) or cve.get("id") or "UNKNOWN"
    summary = (cve.get("summary") or cve.get("description") or (cve.get("cve", {}) or {}).get("description") or "No description available.")
    published = cve.get("Published") or cve.get("published") or cve.get("publishedDate") or "Unknown date"
    cvss = cve.get("cvss") or cve.get("cvss_v3") or cve.get("cvss-score") or "N/A"

    references_raw = cve.get("references") or cve.get("refs") or cve.get("references_data") or []
    if not isinstance(references_raw, list):
        references_raw = [references_raw]
    reference_strs = [ref_to_str(r) for r in references_raw if r]
    ref_texts = [r for r in reference_strs if r]
    ref_text = "\n".join(ref_texts[:3]) if ref_texts else "No references available."

    msg = (
        f"🚨 *New CVE Alert!*\n\n"
        f"*ID:* `{cve_id}`\n"
        f"*Published:* {published}\n"
        f"*CVSS:* {cvss}\n"
        f"*Description:* {summary}\n\n"
        f"*References:*\n{ref_text}\n\n"
        f"[More Info](https://cve.circl.lu/cve/{cve_id})"
    )
    return msg

# --- MAIN LOGIC ---
def main() -> None:
    last_seen = load_json(LAST_SEEN_FILE, [])
    if not isinstance(last_seen, list):
        last_seen = []

    subscribers = load_json(SUBSCRIBERS_FILE, [])
    if not isinstance(subscribers, list):
        subscribers = []

    subscribers = handle_start_commands(subscribers)
    save_json(SUBSCRIBERS_FILE, subscribers)

    latest_cves = fetch_latest_cves()
    if not latest_cves:
        logging.info("No CVEs fetched.")
        return

    new_cves: List[Dict[str, Any]] = []
    for cve in latest_cves:
        cve_id = extract_cve_id(cve)
        if not cve_id:
            logging.warning("Skipping malformed CVE entry: %s", cve)
            continue
        if cve_id not in last_seen:
            new_cves.append(cve)

    logging.info("Found %d new CVEs to send.", len(new_cves))

    if new_cves:
        for cve in new_cves:
            message = format_cve_message(cve)
            for chat_id in subscribers:
                try:
                    send_message(chat_id, message)
                except Exception as e:
                    logging.error("Failed to send CVE to %s: %s", chat_id, e)

        # Update last_seen to the most recent 50 ids from latest_cves in order
        updated_ids: List[str] = []
        for cve in latest_cves:
            cid = extract_cve_id(cve)
            if cid:
                updated_ids.append(cid)
            if len(updated_ids) >= 50:
                break
        save_json(LAST_SEEN_FILE, updated_ids)
        logging.info("Updated last_seen with %d IDs.", len(updated_ids))

if __name__ == "__main__":
    main()
