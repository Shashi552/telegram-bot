# 🛡️ Telegram CVE Alert Bot (Free, Serverless)

This bot automatically fetches new vulnerabilities (CVEs) every 2 hours and sends them to all Telegram subscribers.

---

## 🔧 Setup Steps

1. **Create your Telegram Bot**
   - Go to [@BotFather](https://t.me/BotFather) on Telegram.
   - Run `/newbot` and follow the prompts.
   - Copy your bot token.

2. **Set up GitHub Repo**
   - Create a new repo and add these files (`bot.py`, `requirements.txt`, `.github/workflows/poller.yml`).
   - Go to `Settings → Secrets → Actions`.
   - Add a new secret:
     - Name: `TELEGRAM_TOKEN`
     - Value: your bot token.

3. **First Run**
   - Commit all files and push.
   - Go to the “Actions” tab and run the workflow manually once (`Run workflow`).

4. **Subscribe**
   - Send `/start` to your bot on Telegram to subscribe.
   - You’ll get new CVEs every 2 hours automatically.

---

## 📘 Notes
- Stores state in `last_seen.json` and `subscribers.json`.
- No VPS needed; runs on GitHub’s free Actions infrastructure.
- You can adjust the schedule in `.github/workflows/poller.yml`.
