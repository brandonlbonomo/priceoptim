import os
import json
import re
import base64
import threading
import time as _time
from email.utils import parsedate_to_datetime
from flask import Flask, jsonify, request, redirect, send_file
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build as google_build
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import plaid
from plaid.api import plaid_api
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest
from plaid.model.transactions_get_request import TransactionsGetRequest
from plaid.model.transactions_get_request_options import TransactionsGetRequestOptions
from plaid.model.accounts_balance_get_request import AccountsBalanceGetRequest
from plaid.model.item_webhook_update_request import ItemWebhookUpdateRequest
from plaid.model.transactions_refresh_request import TransactionsRefreshRequest
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, origins="*")

PLAID_ENV         = os.getenv("PLAID_ENV", "development")
PLAID_CLIENT_ID   = os.getenv("PLAID_CLIENT_ID")
PLAID_SECRET      = os.getenv("PLAID_SECRET")
PLAID_WEBHOOK_URL = os.getenv("PLAID_WEBHOOK_URL", "")  # e.g. https://your-app.onrender.com/api/webhook

env_map = {
    "sandbox":     "https://sandbox.plaid.com",
    "development": "https://development.plaid.com",
    "production":  "https://production.plaid.com",
}

configuration = plaid.Configuration(
    host=env_map.get(PLAID_ENV, "https://development.plaid.com"),
    api_key={"clientId": PLAID_CLIENT_ID, "secret": PLAID_SECRET}
)
api_client   = plaid.ApiClient(configuration)
plaid_client = plaid_api.PlaidApi(api_client)

PLAID_HOST = env_map.get(PLAID_ENV, "https://development.plaid.com")
print(f"🏦 Plaid env  : {PLAID_ENV}")
print(f"🌐 Plaid host : {PLAID_HOST}")
print(f"🔑 Client ID  : {PLAID_CLIENT_ID[:6]}..." if PLAID_CLIENT_ID else "⚠️  PLAID_CLIENT_ID not set")
print(f"🪝 Webhook URL: {PLAID_WEBHOOK_URL or '(not set — webhooks disabled)'}")

# ── Gmail OAuth config ────────────────────────────────────────
GMAIL_CLIENT_ID     = os.getenv("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET", "")
GMAIL_REDIRECT_URI  = os.getenv("GMAIL_REDIRECT_URI", "")
GMAIL_SCOPES        = ["https://www.googleapis.com/auth/gmail.readonly"]
print(f"📧 Gmail client : {GMAIL_CLIENT_ID[:6]}..." if GMAIL_CLIENT_ID else "⚠️  GMAIL_CLIENT_ID not set")

# OAuth states stored in persistent file store so all gunicorn workers share them

# ── Persistent store ─────────────────────────────────────────
# store = {
#   "accounts": [ { "access_token": "...", "item_id": "...", "cursor": "...", "name": "..." } ]
# }
# Use persistent disk if available, fall back to local
import os as _os
STORE_FILE = "/data/plaid_store.json" if _os.path.isdir("/data") else "plaid_store.json"
print(f"Store file: {STORE_FILE}")
STORE_ENV   = "PLAID_STORE_JSON"  # Render env var — survives deploys and filesystem wipes

def load_store():
    # Priority: 1) disk file  2) env var backup  3) empty
    try:
        with open(STORE_FILE, "r") as f:
            data = json.load(f)
            if "accounts" not in data:
                data["accounts"] = []
            return data
    except Exception:
        pass
    # Disk file missing (e.g. after redeploy) — try env var backup
    try:
        raw = os.environ.get(STORE_ENV, "")
        if raw:
            data = json.loads(raw)
            if "accounts" not in data:
                data["accounts"] = []
            print("✅ Loaded store from env var backup")
            # Restore to disk immediately
            with open(STORE_FILE, "w") as f:
                json.dump(data, f)
            return data
    except Exception as e:
        print(f"Env var restore failed: {e}")
    return {"accounts": []}

def save_store(data):
    # Save to disk
    try:
        with open(STORE_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print("Failed to save store to disk:", e)
    # Also update env var via Render API if RENDER_API_KEY and RENDER_SERVICE_ID are set
    # This keeps the env var in sync so it survives the next redeploy
    try:
        api_key    = os.environ.get("RENDER_API_KEY", "")
        service_id = os.environ.get("RENDER_SERVICE_ID", "")
        if api_key and service_id:
            import urllib.request
            # Get current env vars
            req = urllib.request.Request(
                f"https://api.render.com/v1/services/{service_id}/env-vars",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                existing = json.loads(r.read())
            # Find and update PLAID_STORE_JSON
            env_list = existing if isinstance(existing, list) else existing.get("envVars", [])
            updated = False
            for ev in env_list:
                if ev.get("key") == STORE_ENV:
                    ev["value"] = json.dumps(data)
                    updated = True
            if not updated:
                env_list.append({"key": STORE_ENV, "value": json.dumps(data)})
            patch = urllib.request.Request(
                f"https://api.render.com/v1/services/{service_id}/env-vars",
                data=json.dumps(env_list).encode(),
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                method="PUT"
            )
            with urllib.request.urlopen(patch, timeout=5):
                pass
            print("✅ Env var backup updated")
    except Exception as e:
        print(f"Env var backup skipped: {e}")

# Don't cache store in memory — always read/write disk so nothing is lost on restart
# store global only used as fallback; all routes call load_store() directly

# ── Frontend ──────────────────────────────────────────────────
@app.route("/")
def frontend():
    response = app.make_response(app.send_static_file("index.html"))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ── PWA manifest ──────────────────────────────────────────────
@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "Property Pigeon",
        "short_name": "Pigeon",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#f5f5f7",
        "theme_color": "#1a1a2e",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
        ]
    })

@app.route("/icon-192.png")
def icon192():
    return send_file("icon-192.png", mimetype="image/png")

@app.route("/icon-512.png")
def icon512():
    return send_file("icon-512.png", mimetype="image/png")

# ── Health ────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    store = load_store()
    return jsonify({
        "ok":               True,
        "plaid_env":        PLAID_ENV,
        "plaid_host":       PLAID_HOST,
        "webhook_url":      PLAID_WEBHOOK_URL or None,
        "webhooks_enabled": bool(PLAID_WEBHOOK_URL),
        "account_count":    len(store["accounts"]),
        "transaction_count": len(store.get("transactions", {})),
        "accounts":         [a.get("name") for a in store["accounts"]],
    })

# ── Store diagnostics ─────────────────────────────────────────
@app.route("/api/debug")
def debug():
    store = load_store()
    txs = list(store.get("transactions", {}).values())
    dates = sorted([t["date"] for t in txs if t.get("date")])
    # Per-account breakdown
    by_account = {}
    for t in txs:
        acc = t.get("account", "unknown")
        if acc not in by_account:
            by_account[acc] = {"count": 0, "newest": "", "oldest": "9999"}
        by_account[acc]["count"] += 1
        d = t.get("date", "")
        if d > by_account[acc]["newest"]: by_account[acc]["newest"] = d
        if d < by_account[acc]["oldest"]: by_account[acc]["oldest"] = d
    return jsonify({
        "total_transactions": len(txs),
        "oldest_date":        dates[0]  if dates else None,
        "newest_date":        dates[-1] if dates else None,
        "by_account":         by_account,
        "cursors":            {a["name"]: (a.get("cursor") or "")[:40] + "..." if a.get("cursor") else None
                               for a in store["accounts"]},
    })

# ── Link status ───────────────────────────────────────────────
@app.route("/api/link-status")
def link_status():
    store = load_store()
    accounts = [{"item_id": a["item_id"], "name": a.get("name", "Bank Account")} for a in store["accounts"]]
    return jsonify({"linked": len(store["accounts"]) > 0, "accounts": accounts})

# ── Create link token ─────────────────────────────────────────
@app.route("/api/create-link-token", methods=["POST"])
def create_link_token():
    store = load_store()
    try:
        kwargs = dict(
            user=LinkTokenCreateRequestUser(client_user_id="pigeon-user"),
            client_name="Property Pigeon",
            products=[Products("transactions")],
            country_codes=[CountryCode("US")],
            language="en",
        )
        if PLAID_WEBHOOK_URL:
            kwargs["webhook"] = PLAID_WEBHOOK_URL
        req = LinkTokenCreateRequest(**kwargs)
        response = plaid_client.link_token_create(req)
        return jsonify({"link_token": response["link_token"]})
    except Exception as e:
        print("create-link-token error:", str(e))
        return jsonify({"error": str(e)}), 500

# ── Exchange token ────────────────────────────────────────────
@app.route("/api/exchange-token", methods=["POST"])
def exchange_token():
    store = load_store()
    public_token  = request.json.get("public_token")
    account_name  = request.json.get("account_name", "Bank Account")
    if not public_token:
        return jsonify({"error": "public_token required"}), 400
    try:
        response = plaid_client.item_public_token_exchange(
            ItemPublicTokenExchangeRequest(public_token=public_token)
        )
        access_token = response["access_token"]
        item_id      = response["item_id"]

        # Check if already linked — keep cursor so Plaid doesn't replay old transactions
        existing = next((a for a in store["accounts"] if a["item_id"] == item_id), None)
        if existing:
            existing["access_token"] = access_token
            existing["name"]         = account_name
            # DO NOT reset cursor — that causes transaction duplication
        else:
            store["accounts"].append({
                "access_token": access_token,
                "item_id":      item_id,
                "cursor":       None,  # None = start from beginning (first link only)
                "name":         account_name,
            })

        save_store(store)
        print(f"✅ Linked: {account_name} ({item_id})")
        return jsonify({"ok": True, "item_id": item_id})
    except Exception as e:
        print("exchange-token error:", str(e))
        return jsonify({"error": str(e)}), 500

# ── Remove account ────────────────────────────────────────────
@app.route("/api/remove-account", methods=["POST"])
def remove_account():
    store = load_store()
    item_id = request.json.get("item_id")
    store["accounts"] = [a for a in store["accounts"] if a["item_id"] != item_id]
    save_store(store)
    return jsonify({"ok": True})

# ── Sync core logic (used by route + scheduler) ───────────────
def run_sync():
    """Pull latest transactions from Plaid for all connected accounts.
    Returns a summary dict; raises no exceptions (errors are logged per-account)."""
    store = load_store()
    if not store["accounts"]:
        print("Scheduled sync: no accounts linked, skipping.")
        return {"total_stored": 0, "total": 0}

    tx_store = store.get("transactions", {})
    all_added, all_modified, all_removed_ids = [], [], []

    for account in store["accounts"]:
        name = account.get("name", "Bank Account")
        try:
            added, modified, removed = [], [], []
            cursor   = account.get("cursor")
            has_more = True
            page     = 0

            print(f"🔄 Syncing {name} — cursor={'set' if cursor else 'none (full sync)'}")

            while has_more:
                page += 1
                kwargs = {"access_token": account["access_token"], "count": 500}
                if cursor:
                    kwargs["cursor"] = cursor
                try:
                    response = plaid_client.transactions_sync(TransactionsSyncRequest(**kwargs))
                except Exception as sync_err:
                    err_str = str(sync_err)
                    # If cursor is invalid/expired, reset it and retry as a full sync
                    if cursor and ("INVALID_CURSOR" in err_str or "cursor" in err_str.lower()):
                        print(f"⚠️  Invalid cursor for {name} — resetting and retrying full sync")
                        account["cursor"] = None
                        cursor = None
                        save_store(store)
                        response = plaid_client.transactions_sync(
                            TransactionsSyncRequest(access_token=account["access_token"], count=500)
                        )
                    else:
                        raise
                data          = response.to_dict()
                page_added    = data.get("added",    [])
                page_modified = data.get("modified", [])
                page_removed  = data.get("removed",  [])
                added    += page_added
                modified += page_modified
                removed  += page_removed
                has_more  = data.get("has_more", False)
                cursor    = data.get("next_cursor")
                print(f"  Page {page}: +{len(page_added)} added, "
                      f"~{len(page_modified)} modified, -{len(page_removed)} removed"
                      f"{', more…' if has_more else ''}")

            account["cursor"] = cursor
            print(f"  ✅ {name}: {len(added)} added, {len(modified)} modified, "
                  f"{len(removed)} removed | cursor={'set' if cursor else 'none'}")

            def normalize(tx):
                amount = tx.get("amount", 0)
                return {
                    "id":      tx.get("transaction_id"),
                    "date":    str(tx.get("date", "")),
                    "payee":   tx.get("merchant_name") or tx.get("name", ""),
                    "amount":  amount,
                    "type":    "out" if amount > 0 else "in",
                    "pending": tx.get("pending", False),
                    "account": account.get("name", "Bank Account"),
                }

            for tx in added:
                n = normalize(tx)
                if n["id"]:
                    tx_store[n["id"]] = n   # store pending AND posted
            for tx in modified:
                n = normalize(tx)
                if n["id"]:
                    tx_store[n["id"]] = n
            for r in removed:
                rid = r.get("transaction_id")
                if rid and rid in tx_store:
                    del tx_store[rid]
                    all_removed_ids.append(rid)

            all_added    += [normalize(t) for t in added]
            all_modified += [normalize(t) for t in modified]

        except Exception as e:
            print(f"Sync error for {account.get('name')}: {e}")
            continue

    store["transactions"] = tx_store
    save_store(store)

    return {
        "added":        all_added,
        "modified":     all_modified,
        "removed":      all_removed_ids,
        "total":        len(all_added),
        "total_stored": len(tx_store),
    }

# ── Sync all accounts ─────────────────────────────────────────
@app.route("/api/transactions/sync")
def sync_transactions():
    store = load_store()
    if not store["accounts"]:
        return jsonify({"error": "No bank account linked yet"}), 400
    result = run_sync()
    return jsonify(result)

# ── Force Plaid to re-poll the bank ───────────────────────────
# Requires "transactions_refresh" product enabled in Plaid dashboard.
# Tells Plaid to immediately fetch fresh data from the bank, then Plaid
# fires a SYNC_UPDATES_AVAILABLE webhook which triggers run_sync().
@app.route("/api/transactions/refresh", methods=["POST"])
def refresh_transactions():
    store = load_store()
    if not store["accounts"]:
        return jsonify({"error": "No bank account linked yet"}), 400
    results, errors = [], []
    for account in store["accounts"]:
        try:
            plaid_client.transactions_refresh(TransactionsRefreshRequest(
                access_token=account["access_token"]
            ))
            results.append(account.get("name"))
            print(f"🔄 Transactions refresh triggered for {account.get('name')}")
        except Exception as e:
            err = f"{account.get('name')}: {str(e)}"
            print(f"❌ Transactions refresh error: {err}")
            errors.append(err)
    return jsonify({
        "ok":        len(errors) == 0,
        "refreshed": results,
        "errors":    errors,
        "note":      "Plaid will fire SYNC_UPDATES_AVAILABLE webhook within minutes, "
                     "which auto-syncs new transactions.",
    })

# ── Plaid webhook receiver ────────────────────────────────────────────────
# Plaid calls this URL when new transaction data is available.
# Set PLAID_WEBHOOK_URL=https://<your-host>/api/webhook and then call
# /api/update-webhook once to register it on all existing linked items.
#
# Security note: Plaid signs webhooks with a JWT in the Plaid-Verification
# header. Full JWT verification is omitted here; instead we validate that
# the item_id is one we actually own before acting on the payload.
@app.route("/api/webhook", methods=["POST"])
def plaid_webhook():
    data         = request.get_json(silent=True) or {}
    webhook_type = data.get("webhook_type", "")
    webhook_code = data.get("webhook_code", "")
    item_id      = data.get("item_id", "")

    print(f"📩 Plaid webhook: {webhook_type}/{webhook_code}  item={item_id}")

    # Only act on transaction webhooks
    if webhook_type != "TRANSACTIONS":
        return jsonify({"ok": True, "action": "ignored"})

    SYNC_CODES = {
        "SYNC_UPDATES_AVAILABLE",  # primary code for transactions/sync flow
        "INITIAL_UPDATE",          # fired after a new item is linked
        "HISTORICAL_UPDATE",       # fired when 2-year history is ready
        "DEFAULT_UPDATE",          # new transactions (legacy code, still fired)
        "TRANSACTIONS_REMOVED",    # transactions deleted from Plaid
    }
    if webhook_code not in SYNC_CODES:
        return jsonify({"ok": True, "action": "ignored"})

    # Verify this item_id belongs to an account we actually own
    store = load_store()
    if item_id and not any(a["item_id"] == item_id for a in store["accounts"]):
        print(f"⚠️  Webhook item_id {item_id} not found in store — ignoring")
        return jsonify({"ok": True, "action": "unknown_item"})

    # Paginate through ALL available updates (run_sync loops has_more automatically)
    try:
        result = run_sync()
        print(f"✅ Webhook sync done: {result.get('total', 0)} new, "
              f"{result.get('total_stored', 0)} total stored")
        return jsonify({
            "ok":          True,
            "action":      "synced",
            "new":         result.get("total", 0),
            "total_stored": result.get("total_stored", 0),
        })
    except Exception as e:
        print(f"❌ Webhook sync error: {e}")
        return jsonify({"error": str(e)}), 500


# ── Register webhook on existing Plaid items ──────────────────────────────
# Call this once after setting PLAID_WEBHOOK_URL to push the URL to every
# already-linked item. New links pick it up automatically via create_link_token.
@app.route("/api/update-webhook", methods=["POST"])
def update_webhook():
    store       = load_store()
    webhook_url = (request.get_json(silent=True) or {}).get("webhook_url") or PLAID_WEBHOOK_URL
    if not webhook_url:
        return jsonify({"error": "webhook_url required (or set PLAID_WEBHOOK_URL env var)"}), 400

    updated, errors = [], []
    for account in store["accounts"]:
        try:
            plaid_client.item_webhook_update(
                ItemWebhookUpdateRequest(
                    access_token=account["access_token"],
                    webhook=webhook_url,
                )
            )
            updated.append(account.get("name", account["item_id"]))
            print(f"✅ Webhook registered for {account.get('name')}: {webhook_url}")
        except Exception as e:
            err = f"{account.get('name')}: {str(e)}"
            print(f"❌ update-webhook error: {err}")
            errors.append(err)

    return jsonify({"ok": True, "webhook_url": webhook_url, "updated": updated, "errors": errors})


# ── Historical pull — fetches up to 2 years back via transactions/get ────
# Call this once after linking a new account to backfill history.
# transactions/sync alone only returns ~90 days on first call.
@app.route("/api/transactions/historical", methods=["POST"])
def historical_pull():
    store = load_store()
    item_id = request.json.get("item_id")  # optional: pull for specific account only
    if not store["accounts"]:
        return jsonify({"error": "No accounts linked"}), 400

    from datetime import date
    # Request all available history — Plaid will return whatever it has
    # (typically up to 24 months in production; sandbox may vary).
    start_date = date(2000, 1, 1)
    end_date   = date.today()

    tx_store = store.get("transactions", {})
    total_added = 0
    errors = []

    accounts_to_pull = [a for a in store["accounts"] if not item_id or a["item_id"] == item_id]

    for account in accounts_to_pull:
        try:
            offset = 0
            batch_size = 500
            while True:
                options = TransactionsGetRequestOptions(
                    count=batch_size,
                    offset=offset,
                    include_personal_finance_category=True
                )
                req = TransactionsGetRequest(
                    access_token=account["access_token"],
                    start_date=start_date,
                    end_date=end_date,
                    options=options
                )
                response = plaid_client.transactions_get(req)
                data = response.to_dict()
                txs  = data.get("transactions", [])
                total_txs = data.get("total_transactions", 0)

                for tx in txs:
                    tid    = tx.get("transaction_id")
                    amount = tx.get("amount", 0)
                    if not tid:
                        continue
                    tx_store[tid] = {
                        "id":      tid,
                        "date":    str(tx.get("date", "")),
                        "payee":   tx.get("merchant_name") or tx.get("name", ""),
                        "amount":  amount,
                        "type":    "out" if amount > 0 else "in",
                        "pending": tx.get("pending", False),
                        "account": account.get("name", "Bank Account"),
                    }
                    total_added += 1

                offset += len(txs)
                if offset >= total_txs or not txs:
                    break

            print(f"✅ Historical pull: {account.get('name')} — {offset} transactions fetched")

        except Exception as e:
            err = f"{account.get('name')}: {str(e)}"
            print(f"❌ Historical pull error: {err}")
            errors.append(err)

    store["transactions"] = tx_store
    save_store(store)
    return jsonify({
        "ok": True,
        "total_stored": len(tx_store),
        "pulled": total_added,
        "errors": errors,
    })

# ── Delete transactions (bulk) ───────────────────────────────
@app.route("/api/transactions/delete", methods=["POST"])
def delete_transactions():
    store = load_store()
    ids = request.json.get("ids", [])
    tx_store = store.get("transactions", {})
    if ids == "__ALL__":
        deleted = len(tx_store)
        store["transactions"] = {}
    else:
        deleted = 0
        for tid in ids:
            if tid in tx_store:
                del tx_store[tid]
                deleted += 1
        store["transactions"] = tx_store
    save_store(store)
    return jsonify({"ok": True, "deleted": deleted})

# ── Get all stored transactions (called on page load) ─────────
@app.route("/api/transactions/all")
def get_all_transactions():
    store = load_store()
    tx_store = store.get("transactions", {})
    return jsonify({"transactions": list(tx_store.values())})

# ── Tags ──────────────────────────────────────────────────────
@app.route("/api/tags", methods=["GET"])
def get_tags():
    store = load_store()
    return jsonify({"tags": store.get("tags", {})})

@app.route("/api/tags", methods=["POST"])
def save_tags():
    store = load_store()
    store["tags"] = request.json.get("tags", {})
    save_store(store)
    return jsonify({"ok": True})

# ── Manual Income ──────────────────────────────────────────────
@app.route("/api/manual-income", methods=["GET"])
def get_manual_income():
    store = load_store()
    return jsonify({"manual": store.get("manual_income", {})})

@app.route("/api/manual-income", methods=["POST"])
def save_manual_income():
    store = load_store()
    store["manual_income"] = request.json.get("manual", {})
    save_store(store)
    return jsonify({"ok": True})

# ── Balances ──────────────────────────────────────────────────
@app.route("/api/balances")
def balances():
    store = load_store()
    if not store["accounts"]:
        return jsonify({"error": "No bank account linked yet"}), 400
    all_accounts = []
    for account in store["accounts"]:
        try:
            response = plaid_client.accounts_balance_get(
                AccountsBalanceGetRequest(access_token=account["access_token"])
            )
            for a in response["accounts"]:
                all_accounts.append({
                    "bank":      account.get("name", "Bank Account"),
                    "name":      a["name"],
                    "type":      str(a["type"]),
                    "current":   a["balances"]["current"],
                    "available": a["balances"].get("available"),
                    "currency":  a["balances"].get("iso_currency_code", "USD"),
                })
        except Exception as e:
            print(f"Balance error for {account.get('name')}: {e}")
    return jsonify({"accounts": all_accounts})

@app.route("/api/rules", methods=["GET"])
def get_rules():
    store = load_store()
    return jsonify({"rules": store.get("rules", {})})

@app.route("/api/rules", methods=["POST"])
def save_rules():
    store = load_store()
    store["rules"] = request.json.get("rules", {})
    save_store(store)
    return jsonify({"ok": True})

@app.route("/api/settings", methods=["GET"])
def get_settings():
    store = load_store()
    return jsonify({"settings": store.get("settings", {})})

@app.route("/api/settings", methods=["POST"])
def save_settings():
    store = load_store()
    store["settings"] = request.json.get("settings", {})
    save_store(store)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════
# GMAIL OAUTH + INVENTORY
# ══════════════════════════════════════════════════════════════

def _gmail_flow():
    """Build an OAuth2 flow from env-var credentials."""
    client_config = {"web": {
        "client_id":     GMAIL_CLIENT_ID,
        "client_secret": GMAIL_CLIENT_SECRET,
        "auth_uri":      "https://accounts.google.com/o/oauth2/auth",
        "token_uri":     "https://oauth2.googleapis.com/token",
        "redirect_uris": [GMAIL_REDIRECT_URI],
    }}
    return Flow.from_client_config(client_config, scopes=GMAIL_SCOPES,
                                   redirect_uri=GMAIL_REDIRECT_URI)


def _get_gmail_credentials():
    """Load stored credentials, refresh the access token only when actually expired."""
    from datetime import datetime, timezone
    store = load_store()
    cd    = store.get("gmail_credentials")
    # Fallback: GMAIL_CREDENTIALS_JSON env var survives redeploys even on ephemeral filesystems
    if not cd:
        raw = os.environ.get("GMAIL_CREDENTIALS_JSON", "").strip()
        if raw:
            try:
                cd = json.loads(raw)
                print("📧 Loaded Gmail credentials from GMAIL_CREDENTIALS_JSON env var")
            except Exception as e:
                print(f"⚠️ GMAIL_CREDENTIALS_JSON parse error: {e}")
    if not cd:
        return None
    # Reconstruct expiry so creds.expired is accurate (None expiry = always-expired bug)
    expiry = None
    if cd.get("expiry"):
        try:
            # google-auth compares expiry against utcnow() which is naive UTC —
            # keep it naive too, otherwise we get offset-naive vs offset-aware error
            expiry = datetime.fromisoformat(cd["expiry"])
            if expiry.tzinfo is not None:
                expiry = expiry.replace(tzinfo=None)
        except Exception:
            pass
    creds = Credentials(
        token         = cd.get("token"),
        refresh_token = cd.get("refresh_token"),
        token_uri     = cd.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id     = GMAIL_CLIENT_ID,
        client_secret = GMAIL_CLIENT_SECRET,
        scopes        = GMAIL_SCOPES,
        expiry        = expiry,
    )
    if creds.expired and creds.refresh_token:
        print("🔄 Gmail token expired/unknown — refreshing…")
        try:
            creds.refresh(GoogleAuthRequest())
            store["gmail_credentials"]["token"]  = creds.token
            exp = creds.expiry
            store["gmail_credentials"]["expiry"] = exp.replace(tzinfo=None).isoformat() if exp else None
            save_store(store)
            print(f"✅ Gmail token refreshed — new expiry: {creds.expiry}")
        except Exception as refresh_err:
            print(f"⚠️ Token refresh failed ({refresh_err}) — trying existing token as-is")
            # The existing token might still be valid; let the API call tell us if not
    return creds


# ── GET /api/gmail/auth ──────────────────────────────────────
@app.route("/api/gmail/auth")
def gmail_auth():
    if not GMAIL_CLIENT_ID or not GMAIL_CLIENT_SECRET:
        return jsonify({"error": "GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET not set"}), 500
    if not GMAIL_REDIRECT_URI:
        return jsonify({"error": "GMAIL_REDIRECT_URI not set"}), 500
    try:
        flow = _gmail_flow()
        auth_url, state = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent"
        )
        # Store state in persistent store so all gunicorn workers can validate it
        store = load_store()
        oauth_states = store.get("oauth_states", {})
        oauth_states[state] = True
        store["oauth_states"] = oauth_states
        save_store(store)
        return redirect(auth_url)
    except Exception as e:
        print(f"❌ gmail_auth error: {e}")
        return jsonify({"error": str(e)}), 500


# ── GET /api/gmail/callback ──────────────────────────────────
@app.route("/api/gmail/callback")
def gmail_callback():
    error = request.args.get("error", "")
    if error:
        print(f"❌ OAuth denied by user: {error}")
        return f"""<html><body style="font-family:sans-serif;text-align:center;padding:60px">
<h2>❌ Gmail connection denied</h2><p>{error}</p><p>You can close this tab.</p></body></html>"""
    state = request.args.get("state", "")
    code  = request.args.get("code",  "")
    # Validate state from persistent store (works across gunicorn workers)
    store = load_store()
    oauth_states = store.get("oauth_states", {})
    if state not in oauth_states:
        print(f"❌ Invalid OAuth state: {state!r}")
        return jsonify({"error": "Invalid OAuth state — possible CSRF"}), 400
    del oauth_states[state]
    store["oauth_states"] = oauth_states
    try:
        flow = _gmail_flow()
        flow.fetch_token(code=code)
        creds = flow.credentials
        store["gmail_credentials"] = {
            "token":         creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri":     creds.token_uri,
            # Store expiry as naive UTC — google-auth compares against naive utcnow()
            "expiry": creds.expiry.replace(tzinfo=None).isoformat() if creds.expiry else None,
        }
        save_store(store)
        creds_json = json.dumps(store["gmail_credentials"])
        print(f"✅ Gmail OAuth connected — token expires: {creds.expiry}")
        print(f"📋 Set this in Render env vars to survive redeploys:")
        print(f"   GMAIL_CREDENTIALS_JSON={creds_json}")
    except Exception as e:
        print(f"❌ gmail_callback fetch_token error: {e}")
        return f"""<html><body style="font-family:sans-serif;text-align:center;padding:60px">
<h2>❌ Gmail connection failed</h2><p>{e}</p><p>Close this tab and try again.</p></body></html>""", 500

    # Kick off an immediate sync — non-daemon so it isn't killed if the
    # response is returned before the thread finishes
    threading.Thread(target=run_gmail_sync, daemon=False).start()

    return f"""<html><body style="font-family:sans-serif;padding:40px;max-width:640px;margin:auto">
<h2>✅ Gmail connected!</h2>
<p>Importing your Amazon orders now — check the Inventory tab in a moment.</p>
<hr style="margin:24px 0">
<p style="font-size:13px;color:#555"><strong>To make this permanent across server restarts:</strong><br>
Copy the value below and add it as a Render environment variable named
<code>GMAIL_CREDENTIALS_JSON</code>.</p>
<textarea readonly style="width:100%;height:80px;font-size:11px;font-family:monospace;padding:8px;box-sizing:border-box">{creds_json}</textarea>
<p style="font-size:12px;color:#888">You only need to do this once. After setting the env var, credentials survive redeploys automatically.</p>
</body></html>"""


# ── Email parser ─────────────────────────────────────────────
def _parse_amazon_email(msg_data):
    """Extract order details from an Amazon ship-confirm Gmail message."""
    headers  = {h["name"]: h["value"]
                for h in msg_data.get("payload", {}).get("headers", [])}
    subject  = headers.get("Subject", "")
    date_str = headers.get("Date", "")

    order_date = None
    try:
        order_date = parsedate_to_datetime(date_str).date().isoformat()
    except Exception:
        pass

    # Decode plain-text body
    body = ""
    def _extract(part):
        nonlocal body
        if part.get("mimeType") == "text/plain" and not body:
            raw = part.get("body", {}).get("data", "")
            if raw:
                body = base64.urlsafe_b64decode(raw + "==").decode("utf-8", errors="replace")
        for sub in part.get("parts", []):
            _extract(sub)
    _extract(msg_data.get("payload", {}))

    # Item name — from subject "order of "Widget" has shipped" pattern
    item = ""
    m = re.search(r'order of\s+"?(.+?)"?\s+(?:and \d+|has shipped)', subject, re.I)
    if m:
        item = m.group(1).strip()
    if not item:
        m2 = re.search(r'(?:You ordered|Item ordered|Ordered):\s*(.+)', body, re.I)
        if m2:
            item = m2.group(1).strip()[:120]

    # Order number
    order_num = ""
    m3 = re.search(r'(\d{3}-\d{7}-\d{7})', subject + " " + body)
    if m3:
        order_num = m3.group(1)

    # First dollar amount in body
    price = None
    prices = re.findall(r'\$\s*(\d+\.\d{2})', body)
    if prices:
        price = float(prices[0])

    # Quantity
    qty = 1
    m4 = re.search(r'(?:Qty|Quantity|qty):\s*(\d+)', body, re.I)
    if m4:
        qty = int(m4.group(1))

    return {
        "id":        msg_data["id"],
        "subject":   subject,
        "item":      item or subject,
        "order_num": order_num,
        "price":     price,
        "quantity":  qty,
        "date":      order_date,
        "prop_tag":  None,   # user-assigned property tag
        "source":    "amazon",
    }


def run_gmail_sync():
    """Fetch Amazon ship-confirm emails from Gmail, parse, store in inventory."""
    print("📧 run_gmail_sync starting…")
    creds = _get_gmail_credentials()
    if not creds:
        print("📧 Gmail sync skipped — no credentials stored (visit /api/gmail/auth)")
        return {"synced": 0, "total": 0}

    print(f"📧 Credentials loaded — expired={creds.expired}, has_refresh={bool(creds.refresh_token)}")
    service   = google_build("gmail", "v1", credentials=creds)
    store     = load_store()
    inventory = store.get("inventory", {})
    already   = len(inventory)

    q = ("from:ship-confirm@amazon.com OR from:auto-confirm@amazon.com "
         "OR from:order-update@amazon.com")
    print(f"📧 Querying Gmail: {q}")
    try:
        results = service.users().messages().list(userId="me", q=q, maxResults=500).execute()
    except Exception as api_err:
        print(f"❌ Gmail API list failed: {api_err}")
        raise RuntimeError(f"Gmail API error: {api_err}") from api_err
    messages = results.get("messages", [])
    new_msgs = [m for m in messages if m["id"] not in inventory]
    print(f"📧 {len(messages)} messages matched query, {len(new_msgs)} are new (not yet in inventory)")

    new_count = 0
    errors    = 0
    for ref in new_msgs:
        mid = ref["id"]
        try:
            msg_data = service.users().messages().get(
                userId="me", id=mid, format="full"
            ).execute()
            parsed = _parse_amazon_email(msg_data)
            inventory[mid] = parsed
            new_count += 1
            print(f"  ✅ Parsed: {parsed.get('item','?')[:60]} | {parsed.get('date')} | ${parsed.get('price')}")
        except Exception as e:
            errors += 1
            print(f"  ⚠️  Skipping message {mid}: {e}")

    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    store["inventory"]           = inventory
    store["gmail_last_sync"]     = now_iso
    store["gmail_message_count"] = len(messages)
    save_store(store)
    print(f"✅ Gmail sync done: {new_count} new, {errors} errors, "
          f"{len(inventory)} total (was {already}) | {len(messages)} matched query")
    return {"synced": new_count, "total": len(inventory),
            "message_count": len(messages), "last_sync": now_iso, "errors": errors}


# ── GET /api/gmail/sync ──────────────────────────────────────
@app.route("/api/gmail/sync")
def gmail_sync_route():
    try:
        result = run_gmail_sync()
        return jsonify({"ok": True, **result})
    except Exception as e:
        print(f"❌ Gmail sync error: {e}")
        return jsonify({"error": str(e)}), 500


# ── GET /api/gmail/status ─────────────────────────────────────
@app.route("/api/gmail/status")
def gmail_status():
    store = load_store()
    return jsonify({
        "connected":       bool(store.get("gmail_credentials")),
        "last_sync":       store.get("gmail_last_sync"),
        "inventory_count": len(store.get("inventory", {})),
        "message_count":   store.get("gmail_message_count", 0),
    })


# ── GET /api/gmail/debug ──────────────────────────────────────
# Proves the stored credentials are live and the query actually hits Gmail
@app.route("/api/gmail/debug")
def gmail_debug():
    creds = _get_gmail_credentials()
    if not creds:
        return jsonify({"connected": False, "error": "No credentials stored — visit /api/gmail/auth"})
    try:
        service = google_build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        results = service.users().messages().list(
            userId="me",
            q="from:ship-confirm@amazon.com OR from:auto-confirm@amazon.com OR from:order-update@amazon.com",
            maxResults=5
        ).execute()
        store = load_store()
        return jsonify({
            "connected":           True,
            "email":               profile.get("emailAddress"),
            "gmail_total_msgs":    profile.get("messagesTotal"),
            "amazon_msgs_found":   len(results.get("messages", [])),
            "inventory_stored":    len(store.get("inventory", {})),
            "last_sync":           store.get("gmail_last_sync"),
        })
    except Exception as e:
        print(f"❌ Gmail debug error: {e}")
        return jsonify({"connected": False, "error": str(e)}), 500


# ── GET /api/inventory ───────────────────────────────────────
@app.route("/api/inventory")
def get_inventory():
    store = load_store()
    items = list(store.get("inventory", {}).values())
    items.sort(key=lambda x: x.get("date") or "", reverse=True)
    return jsonify({"inventory": items, "total": len(items)})


# ── POST /api/inventory ──────────────────────────────────────
# Add a manual inventory item or update an existing one's prop_tag
@app.route("/api/inventory", methods=["POST"])
def update_inventory():
    store     = load_store()
    inventory = store.get("inventory", {})
    item      = request.json or {}
    iid       = item.get("id") or f"manual-{int(_time.time()*1000)}"
    if iid in inventory:
        # Merge — allows updating prop_tag without overwriting everything
        inventory[iid].update({k: v for k, v in item.items() if k != "id"})
    else:
        inventory[iid] = {
            "id":        iid,
            "item":      item.get("item", ""),
            "quantity":  item.get("quantity", 1),
            "price":     item.get("price"),
            "date":      item.get("date"),
            "order_num": item.get("order_num", ""),
            "subject":   item.get("item", ""),
            "prop_tag":  item.get("prop_tag"),
            "source":    "manual",
        }
    store["inventory"] = inventory
    save_store(store)
    return jsonify({"ok": True, "id": iid, "item": inventory[iid]})


# ── Daily sync scheduler ──────────────────────────────────────
def scheduled_sync():
    print("⏰ Scheduled daily sync starting...")
    try:
        result = run_sync()
        print(f"✅ Scheduled sync complete — {result.get('total_stored', 0)} transactions stored")
    except Exception as e:
        print(f"❌ Scheduled sync failed: {e}")

def scheduled_gmail_sync():
    print("⏰ Scheduled Gmail sync starting…")
    try:
        result = run_gmail_sync()
        print(f"✅ Scheduled Gmail sync done: {result.get('synced', 0)} new, "
              f"{result.get('total', 0)} total")
    except Exception as e:
        print(f"❌ Scheduled Gmail sync failed: {e}")

scheduler = BackgroundScheduler(daemon=True)
# Plaid fallback sync every 6 hours
scheduler.add_job(scheduled_sync, IntervalTrigger(hours=6), id="periodic_sync", replace_existing=True)
# Gmail inventory sync every 6 hours
scheduler.add_job(scheduled_gmail_sync, IntervalTrigger(hours=6), id="gmail_sync", replace_existing=True)
scheduler.start()
print("⏰ Scheduler started: Plaid + Gmail syncs every 6 hours")

# ── Startup sync ──────────────────────────────────────────────────────────

def startup_sync():
    _time.sleep(4)  # let gunicorn fully start before hitting Plaid
    store    = load_store()
    accounts = store.get("accounts", [])
    tx_count = len(store.get("transactions", {}))
    if not accounts:
        print("🚀 Startup: no accounts linked — skipping sync")
        return
    print(f"🚀 Startup: {len(accounts)} account(s) linked, {tx_count} transactions cached — syncing…")
    try:
        result = run_sync()
        print(f"✅ Startup sync done: {result.get('total', 0)} new, "
              f"{result.get('total_stored', 0)} total stored")
    except Exception as e:
        print(f"❌ Startup sync failed: {e}")

threading.Thread(target=startup_sync, daemon=True).start()
print("🚀 Startup sync scheduled (runs in background after 4s)")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
