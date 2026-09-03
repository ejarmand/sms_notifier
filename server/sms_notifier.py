import os

from flask import Flask, jsonify

from blueprints.auth import auth_bp, initialize_auth
from blueprints.sms import sms_bp
from src.logging_config import get_logger, setup_logging


def create_app():
    setup_logging()
    app = Flask(__name__)
    app.register_blueprint(auth_bp)
    app.register_blueprint(sms_bp)
    initialize_auth()

    @app.get("/health")
    def health_check():
        return jsonify({"status": "healthy"})

    return app


if __name__ == "__main__":
    application = create_app()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    get_logger(__name__).info("Starting development server on %s:%s", host, port)
    application.run(host=host, port=port)
