import os
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import plaid
from plaid.api import plaid_api
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest
from plaid.model.transactions_get_request import TransactionsGetRequest
from plaid.model.transactions_get_request_options import TransactionsGetRequestOptions
from plaid.model.accounts_balance_get_request import AccountsBalanceGetRequest
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, origins="*")

PLAID_ENV       = os.getenv("PLAID_ENV", "development")
PLAID_CLIENT_ID = os.getenv("PLAID_CLIENT_ID")
PLAID_SECRET    = os.getenv("PLAID_SECRET")

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
    return app.send_static_file("index.html")

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
        "ok": True,
        "account_count": len(store["accounts"]),
        "transaction_count": len(store.get("transactions", {})),
        "accounts": [a.get("name") for a in store["accounts"]]
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
        req = LinkTokenCreateRequest(
            user=LinkTokenCreateRequestUser(client_user_id="pigeon-user"),
            client_name="Property Pigeon",
            products=[Products("transactions")],
            country_codes=[CountryCode("US")],
            language="en",
        )
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
        try:
            added, modified, removed = [], [], []
            cursor   = account.get("cursor")
            has_more = True

            while has_more:
                kwargs = {"access_token": account["access_token"], "count": 500}
                if cursor:
                    kwargs["cursor"] = cursor
                response = plaid_client.transactions_sync(TransactionsSyncRequest(**kwargs))
                data     = response.to_dict()
                added    += data.get("added",    [])
                modified += data.get("modified", [])
                removed  += data.get("removed",  [])
                has_more  = data.get("has_more", False)
                cursor    = data.get("next_cursor")

            account["cursor"] = cursor

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
                if n["id"] and not n["pending"]:
                    tx_store[n["id"]] = n
            for tx in modified:
                n = normalize(tx)
                if n["id"]:
                    tx_store[n["id"]] = n
            for r in removed:
                rid = r.get("transaction_id")
                if rid and rid in tx_store:
                    del tx_store[rid]
                    all_removed_ids.append(rid)

            all_added    += [normalize(t) for t in added if not t.get("pending")]
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

# ── Historical pull — fetches up to 2 years back via transactions/get ────
# Call this once after linking a new account to backfill history.
# transactions/sync alone only returns ~90 days on first call.
@app.route("/api/transactions/historical", methods=["POST"])
def historical_pull():
    store = load_store()
    item_id = request.json.get("item_id")  # optional: pull for specific account only
    if not store["accounts"]:
        return jsonify({"error": "No accounts linked"}), 400

    from datetime import date, timedelta
    start_date = date.today() - timedelta(days=730)  # 2 years
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
                    if tx.get("pending"):
                        continue
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
                        "pending": False,
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

# ── Daily sync scheduler ──────────────────────────────────────
def scheduled_sync():
    print("⏰ Scheduled daily sync starting...")
    try:
        result = run_sync()
        print(f"✅ Scheduled sync complete — {result.get('total_stored', 0)} transactions stored")
    except Exception as e:
        print(f"❌ Scheduled sync failed: {e}")

scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(scheduled_sync, CronTrigger(hour=7, minute=0), id="daily_sync", replace_existing=True)
scheduler.start()
print("⏰ Daily sync scheduler started (runs at 07:00 server time)")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
