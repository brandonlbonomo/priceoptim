import os
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
import plaid
from plaid.api import plaid_api
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest
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
STORE_FILE = "plaid_store.json"

def load_store():
    try:
        with open(STORE_FILE, "r") as f:
            data = json.load(f)
            if "accounts" not in data:
                data["accounts"] = []
            return data
    except Exception:
        return {"accounts": []}

def save_store(data):
    try:
        with open(STORE_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print("Failed to save store:", e)

# Don't cache store in memory — always read/write disk so nothing is lost on restart
# store global only used as fallback; all routes call load_store() directly

# ── Frontend ──────────────────────────────────────────────────
@app.route("/")
def frontend():
    return app.send_static_file("index.html")

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

# ── Sync all accounts ─────────────────────────────────────────
@app.route("/api/transactions/sync")
def sync_transactions():
    store = load_store()
    if not store["accounts"]:
        return jsonify({"error": "No bank account linked yet"}), 400

    # Server-side transaction store — keyed by transaction_id, survives code updates
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
                    tx_store[n["id"]] = n  # upsert — ID is the key, no duplication possible
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

    return jsonify({
        "added":        all_added,
        "modified":     all_modified,
        "removed":      all_removed_ids,
        "total":        len(all_added),
        "total_stored": len(tx_store),
    })

# ── Delete transactions (bulk) ───────────────────────────────
@app.route("/api/transactions/delete", methods=["POST"])
def delete_transactions():
    store = load_store()
    ids = request.json.get("ids", [])
    tx_store = store.get("transactions", {})
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

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
