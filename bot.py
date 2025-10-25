import os
import json
import requests
from datetime import datetime

# --- CONFIG ---
BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"
CVE_FEED = "https://cve.circl.lu/api/last"
LAST_SEEN_FILE = "last_seen.json"
SUBSCRIBERS_FILE = "subscribers.json"

# --- LOAD STATE FILES ---
def load_json(filename, default):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

# --- TELEGRAM HELPERS ---
def send_message(chat_id, text):
    requests.post(f"{BASE_URL}/sendMessage", json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"})

def get_updates(offset=None):
    params = {"offset": offset, "timeout": 10}
    resp = requests.get(f"{BASE_URL}/getUpdates", params=params).json()
    return resp.get("result", [])

# --- HANDLE NEW SUBSCRIBERS ---
def handle_start_commands(subscribers):
    print("Checking for /start commands...")
    last_update_id = None
    updates = get_updates()
    for update in updates:
        last_update_id = update["update_id"]
        message = update.get("message", {})
        text = message.get("text", "")
        chat_id = message.get("chat", {}).get("id")
        if text == "/start" and chat_id not in subscribers:
            subscribers.append(chat_id)
            send_message(chat_id, "✅ You have been subscribed to CVE alerts! You'll get new vulnerabilities every 2 hours.")
    if last_update_id:
        requests.get(f"{BASE_URL}/getUpdates", params={"offset": last_update_id + 1})
    return subscribers

# --- FETCH & SEND CVES ---
def fetch_latest_cves():
    resp = requests.get(CVE_FEED)
    if resp.status_code == 200:
        return resp.json()
    return []

def format_cve_message(cve):
    cve_id = cve.get("id") or cve.get("cve", {}).get("CVE_data_meta", {}).get("ID")
    summary = cve.get("summary") or cve.get("description") or "No description available."
    published = cve.get("Published", "Unknown date")
    cvss = cve.get("cvss", "N/A")
    references = cve.get("references", []) or []
    ref_text = "\n".join(references[:3])
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
def main():
    last_seen = load_json(LAST_SEEN_FILE, [])
    subscribers = load_json(SUBSCRIBERS_FILE, [])

    subscribers = handle_start_commands(subscribers)

    latest_cves = fetch_latest_cves()

    # Compare with last seen CVEs
    new_cves = []
    for cve in latest_cves:
        cve_id = cve.get("id") or cve.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        if not cve_id:
            print(f"[WARN] Skipping malformed CVE entry: {cve}")
            continue
        if cve_id not in last_seen:
            new_cves.append(cve)

    print(f"[INFO] Found {len(new_cves)} new CVEs to send.")
    if new_cves:
        for cve in new_cves:
            message = format_cve_message(cve)
            for chat_id in subscribers:
                send_message(chat_id, message)
        last_seen = [cve.get("id") or cve.get("cve", {}).get("CVE_data_meta", {}).get("ID") for cve in latest_cves[:50]]
        print(f"Sent {len(new_cves)} new CVEs.")
    else:
        print("No new CVEs found.")

    save_json(LAST_SEEN_FILE, last_seen)
    save_json(SUBSCRIBERS_FILE, subscribers)

if __name__ == "__main__":
    main()
