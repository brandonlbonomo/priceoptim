import os
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

# Serve index.html from the same folder as app.py
app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, origins="*")

# ── Plaid client setup ───────────────────────────────────────
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
    api_key={
        "clientId": PLAID_CLIENT_ID,
        "secret":   PLAID_SECRET,
    }
)

api_client   = plaid.ApiClient(configuration)
plaid_client = plaid_api.PlaidApi(api_client)

# ── In-memory token store ────────────────────────────────────
store = {
    "access_token": None,
    "item_id":      None,
    "cursor":       None,
}

# ── Serve frontend ────────────────────────────────────────────
@app.route("/")
def frontend():
    return app.send_static_file("index.html")

# ── Health check ─────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"ok": True, "linked": store["access_token"] is not None})

# ── Link status ───────────────────────────────────────────────
@app.route("/api/link-status")
def link_status():
    return jsonify({
        "linked":  store["access_token"] is not None,
        "item_id": store["item_id"],
    })

# ── Step 1: Create link token ─────────────────────────────────
@app.route("/api/create-link-token", methods=["POST"])
def create_link_token():
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
        return jsonify({"error": "Failed to create link token"}), 500

# ── Step 2: Exchange public token ─────────────────────────────
@app.route("/api/exchange-token", methods=["POST"])
def exchange_token():
    public_token = request.json.get("public_token")
    if not public_token:
        return jsonify({"error": "public_token required"}), 400
    try:
        response = plaid_client.item_public_token_exchange(
            ItemPublicTokenExchangeRequest(public_token=public_token)
        )
        store["access_token"] = response["access_token"]
        store["item_id"]      = response["item_id"]
        store["cursor"]       = None
        print("✅ Linked. Item ID:", store["item_id"])
        return jsonify({"ok": True, "item_id": store["item_id"]})
    except Exception as e:
        print("exchange-token error:", str(e))
        return jsonify({"error": "Failed to exchange token"}), 500

# ── Step 3: Sync transactions ─────────────────────────────────
@app.route("/api/transactions/sync")
def sync_transactions():
    if not store["access_token"]:
        return jsonify({"error": "No bank account linked yet"}), 400
    try:
        added, modified, removed = [], [], []
        cursor   = store["cursor"]
        has_more = True

        while has_more:
            kwargs = {"access_token": store["access_token"], "count": 100}
            if cursor:
                kwargs["cursor"] = cursor

            response = plaid_client.transactions_sync(
                TransactionsSyncRequest(**kwargs)
            )
            data = response.to_dict()

            added    += data.get("added",    [])
            modified += data.get("modified", [])
            removed  += data.get("removed",  [])
            has_more  = data.get("has_more", False)
            cursor    = data.get("next_cursor")

        store["cursor"] = cursor

        def normalize(tx):
            amount = tx.get("amount", 0)
            return {
                "id":       tx.get("transaction_id"),
                "date":     str(tx.get("date", "")),
                "payee":    tx.get("merchant_name") or tx.get("name", ""),
                "amount":   amount,
                "type":     "out" if amount > 0 else "in",
                "category": (tx.get("personal_finance_category") or {}).get("primary"),
                "pending":  tx.get("pending", False),
                "property": None,
            }

        return jsonify({
            "added":    [normalize(t) for t in added],
            "modified": [normalize(t) for t in modified],
            "removed":  [r.get("transaction_id") for r in removed],
            "total":    len(added),
        })
    except Exception as e:
        print("sync error:", str(e))
        return jsonify({"error": "Failed to sync transactions"}), 500

# ── Step 4: Account balances ──────────────────────────────────
@app.route("/api/balances")
def balances():
    if not store["access_token"]:
        return jsonify({"error": "No bank account linked yet"}), 400
    try:
        response = plaid_client.accounts_balance_get(
            AccountsBalanceGetRequest(access_token=store["access_token"])
        )
        accounts = []
        for a in response["accounts"]:
            accounts.append({
                "name":      a["name"],
                "type":      str(a["type"]),
                "current":   a["balances"]["current"],
                "available": a["balances"].get("available"),
                "currency":  a["balances"].get("iso_currency_code", "USD"),
            })
        return jsonify({"accounts": accounts})
    except Exception as e:
        print("balances error:", str(e))
        return jsonify({"error": "Failed to fetch balances"}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
