#!/usr/bin/env python3
# bot.py
# Reference: use with workflow ref fa5e664968f37dfe4759bace0fd7152b7fc27307
from __future__ import annotations
import os
import sys
import time
import json
import re
import argparse
import logging
from typing import Any, Dict, List, Optional
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
BASE_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}" if TELEGRAM_TOKEN else ""
CVE_FEED = os.environ.get("CVE_FEED", "https://cve.circl.lu/api/last")
CVE_LOOKUP = os.environ.get("CVE_LOOKUP", "https://cve.circl.lu/api/cve")
STATE_FILE = os.environ.get("STATE_FILE", "state.json")

# digest interval in seconds (default 2 hours)
DIGEST_INTERVAL = int(os.environ.get("DIGEST_INTERVAL_SECONDS", 2 * 60 * 60))

CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d+\b", flags=re.IGNORECASE)


def load_state(path: str) -> Dict[str, Any]:
    default = {"offset": None, "last_seen": [], "last_cve_ts": 0, "subscribers": []}
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if not isinstance(data, dict):
                    return default
                # normalize keys
                return {
                    "offset": data.get("offset"),
                    "last_seen": data.get("last_seen", []) if isinstance(data.get("last_seen", []), list) else [],
                    "last_cve_ts": int(data.get("last_cve_ts", 0)) if data.get("last_cve_ts", 0) is not None else 0,
                    "subscribers": data.get("subscribers", []) if isinstance(data.get("subscribers", []), list) else [],
                }
    except Exception as e:
        logging.warning("Failed to load state %s: %s", path, e)
    return default


def save_state(path: str, data: Dict[str, Any]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error("Failed to write state to %s: %s", path, e)


def ref_to_str(ref: Any) -> str:
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


def send_message(chat_id: int, text: str) -> bool:
    if not TELEGRAM_TOKEN:
        logging.error("TELEGRAM_TOKEN not set; cannot send messages.")
        return False
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    try:
        resp = requests.post(f"{BASE_URL}/sendMessage", json=payload, timeout=10)
        logging.info("sendMessage chat=%s status=%s", chat_id, resp.status_code)
        if resp.status_code != 200:
            logging.error("sendMessage failed: %s", resp.text)
            return False
        return True
    except Exception as e:
        logging.error("Error sending message to %s: %s", chat_id, e)
        return False


def get_updates(offset: Optional[int] = None, timeout: int = 5) -> List[Dict[str, Any]]:
    if not TELEGRAM_TOKEN:
        logging.warning("TELEGRAM_TOKEN not set; skipping getUpdates.")
        return []
    params = {"timeout": timeout}
    if offset is not None:
        params["offset"] = offset
    try:
        resp = requests.get(f"{BASE_URL}/getUpdates", params=params, timeout=timeout + 5)
        data = resp.json()
        return data.get("result", [])
    except Exception as e:
        logging.warning("getUpdates error: %s", e)
    return []


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


def fetch_cve_by_id(cve_id: str) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.get(f"{CVE_LOOKUP}/{cve_id}", timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and data:
                return data
    except Exception as e:
        logging.warning("fetch_cve_by_id error: %s", e)
    return None


def extract_cve_id(cve: Dict[str, Any]) -> Optional[str]:
    if not isinstance(cve, dict):
        return None
    for key in ("id", "ID", "Name", "CVE"):
        v = cve.get(key)
        if isinstance(v, str):
            return v
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


def format_cve_message(cve: Dict[str, Any]) -> str:
    cve_id = str(extract_cve_id(cve) or cve.get("id") or "UNKNOWN")
    summary = (
        cve.get("summary")
        or cve.get("description")
        or (cve.get("cve", {}) or {}).get("description")
        or cve.get("details")
        or "No description available."
    )
    published = cve.get("Published") or cve.get("published") or cve.get("PublishedDate") or "Unknown date"
    cvss = cve.get("cvss") or cve.get("cvss_v3") or "N/A"
    references_raw = cve.get("references") or cve.get("refs") or cve.get("References") or []
    if not isinstance(references_raw, list):
        references_raw = [references_raw]
    reference_strs = [ref_to_str(r) for r in references_raw if r]
    ref_texts = [r for r in reference_strs if r]
    ref_text = "\n".join(ref_texts[:3]) if ref_texts else "No references available."
    msg = (
        f"🚨 *CVE Details*\n\n"
        f"*ID:* `{cve_id}`\n"
        f"*Published:* {published}\n"
        f"*CVSS:* {cvss}\n"
        f"*Description:* {summary}\n\n"
        f"*References:*\n{ref_text}\n\n"
        f"[More Info](https://cve.circl.lu/cve/{cve_id})"
    )
    return msg


def process_updates_once(state: Dict[str, Any]) -> Dict[str, Any]:
    offset = state.get("offset")
    subscribers = state.get("subscribers", [])
    updates = get_updates(offset=offset, timeout=5)
    last_update_id = offset
    if updates:
        logging.info("Processing %d updates", len(updates))
    for u in updates:
        last_update_id = u.get("update_id", last_update_id)
        message = u.get("message") or u.get("edited_message") or {}
        text = (message.get("text") or "").strip()
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if not chat_id:
            continue
        # commands
        if text == "/start":
            if chat_id not in subscribers:
                subscribers.append(chat_id)
                send_message(chat_id, "✅ You have been subscribed to CVE alerts! You'll get new vulnerabilities every 2 hours.")
                logging.info("Subscribed %s", chat_id)
            else:
                send_message(chat_id, "You are already subscribed to CVE alerts.")
            continue
        if text == "/stop":
            if chat_id in subscribers:
                subscribers.remove(chat_id)
                send_message(chat_id, "🛑 You have been unsubscribed. Send /start to subscribe again.")
                logging.info("Unsubscribed %s", chat_id)
            else:
                send_message(chat_id, "You are not currently subscribed.")
            continue
        # CVE query immediate reply
        m = CVE_ID_RE.search(text)
        if m:
            cve_id = m.group(0).upper()
            logging.info("CVE query from %s for %s", chat_id, cve_id)
            cve = fetch_cve_by_id(cve_id)
            if cve:
                send_message(chat_id, format_cve_message(cve))
            else:
                send_message(chat_id, f"No details found for {cve_id}.")
            continue
    # update offset
    if last_update_id is not None:
        state["offset"] = last_update_id + 1
    state["subscribers"] = subscribers
    return state


def maybe_send_digest(state: Dict[str, Any]) -> Dict[str, Any]:
    now = int(time.time())
    last_ts = int(state.get("last_cve_ts", 0) or 0)
    if now - last_ts < DIGEST_INTERVAL:
        logging.debug("Digest not due yet (elapsed %s < %s)", now - last_ts, DIGEST_INTERVAL)
        return state
    logging.info("Digest due: fetching CVE feed")
    latest_cves = fetch_latest_cves()
    if not latest_cves:
        logging.info("No CVEs retrieved")
        return state
    last_seen = state.get("last_seen", [])
    new_cves = []
    for cve in latest_cves:
        cid = extract_cve_id(cve) or cve.get("id")
        if not cid:
            continue
        if cid not in last_seen:
            new_cves.append(cve)
    logging.info("Found %d new CVEs to send", len(new_cves))
    subscribers = state.get("subscribers", [])
    if new_cves and subscribers:
        for cve in new_cves:
            msg = format_cve_message(cve)
            for chat_id in subscribers:
                send_message(chat_id, msg)
    # update last_seen to the most recent 50 ids
    updated_ids = []
    for cve in latest_cves:
        cid = extract_cve_id(cve) or cve.get("id")
        if cid:
            updated_ids.append(cid)
        if len(updated_ids) >= 50:
            break
    state["last_seen"] = updated_ids
    state["last_cve_ts"] = now
    return state


def main_once(state_file: str) -> int:
    state = load_state(state_file)
    state = process_updates_once(state)
    state = maybe_send_digest(state)
    save_state(state_file, state)
    logging.info("Run complete")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Process updates once and exit (for CI/cron)")
    args = parser.parse_args()
    if not TELEGRAM_TOKEN:
        logging.error("TELEGRAM_TOKEN not set. Exiting.")
        sys.exit(1)
    if args.once:
        sys.exit(main_once(STATE_FILE))
    else:
        # fallback: short loop mode for local testing
        logging.info("Running in short-loop mode (not recommended in Actions). Use --once for CI.")
        try:
            while True:
                main_once(STATE_FILE)
                time.sleep(10)
        except KeyboardInterrupt:
            logging.info("Interrupted, exiting")


if __name__ == "__main__":
    main()
