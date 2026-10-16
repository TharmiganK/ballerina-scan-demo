from flask import Flask

from app.auth import auth
from app.documents import documents
from app.orders import legacy, orders
from app.webhooks import webhooks


def create_app() -> Flask:
    app = Flask(__name__)
    for blueprint in (orders, legacy, webhooks, documents, auth):
        app.register_blueprint(blueprint)
    return app
