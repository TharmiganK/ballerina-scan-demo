import uuid

from flask import Blueprint, abort, redirect, request
from flask_cors import CORS

orders = Blueprint("orders", __name__, url_prefix="/orders")
legacy = Blueprint("legacy", __name__, url_prefix="/legacy")

# Vulnerable: ballerina/http:2 (CWE-942) - any origin may call the API with the user's credentials.
CORS(orders, origins="*", supports_credentials=True)

_orders: dict[str, dict] = {}


@orders.get("/")
def list_orders():
    return list(_orders.values())


@orders.get("/<order_id>")
def get_order(order_id: str):
    order = _orders.get(order_id)
    if order is None:
        abort(404)
    return order


@orders.post("/")
def create_order():
    new_order = request.get_json()
    order = {
        "id": str(uuid.uuid4()),
        "customerId": new_order["customerId"],
        "items": new_order["items"],
        "status": "PENDING",
    }
    _orders[order["id"]] = order
    return order, 201


@orders.get("/checkout/<path:return_url>")
def checkout(return_url: str):
    # Vulnerable: ballerina/http:4 (CWE-601) - the client chooses where the browser is sent after checkout.
    return redirect(return_url)


# Vulnerable: ballerina/http:1 (CWE-352) - the legacy sync endpoint answers every HTTP method, including unsafe ones.
@legacy.route("/sync", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def sync():
    return "synced"
