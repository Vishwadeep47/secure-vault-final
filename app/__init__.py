"""SecureVault application factory."""
import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from app.config import BASE_DIR, Config

# The browser only runs our own scripts and styles. No inline code, no outside sites.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


def create_app(test_config=None):
    app = Flask(
        __name__,
        static_folder=os.path.join(BASE_DIR, "static"),
        static_url_path="/static",
        template_folder=os.path.join(BASE_DIR, "templates"),
    )
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # Keys are loaded once at startup and kept in memory (never in the database).
    from app.crypto import keys

    secrets_dir = app.config["SECRETS_DIR"]
    app.config["JWT_SECRET"] = keys.load_or_create_secret("jwt_secret", secrets_dir)
    app.config["AES_KEY"] = keys.load_or_create_secret("vault_key", secrets_dir)

    from app import db

    db.init_app(app)

    from app.admin.routes import admin_bp
    from app.auth.password_routes import password_bp
    from app.auth.routes import auth_bp
    from app.vault.cards import cards_bp
    from app.vault.images import images_bp
    from app.vault.notes import notes_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(password_bp)
    app.register_blueprint(notes_bp)
    app.register_blueprint(images_bp)
    app.register_blueprint(cards_bp)
    app.register_blueprint(admin_bp)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    # ---- reject oversized JSON early (images are limited separately, to 10 MB)
    @app.before_request
    def limit_json_size():
        if request.mimetype == "application/json":
            length = request.content_length
            if length is not None and length > app.config["JSON_MAX_BYTES"]:
                return jsonify(error="Request body too large"), 413

    # ---- errors: plain JSON for the API, never a stack trace or framework page
    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="File too large"), 413

    @app.errorhandler(HTTPException)
    def http_error(error):
        if request.path.startswith("/api/"):
            return jsonify(error=error.name), error.code
        return error

    @app.errorhandler(Exception)
    def unexpected_error(error):
        app.logger.exception("Unhandled error")  # details stay in the server log only
        if request.path.startswith("/api/"):
            return jsonify(error="Internal server error"), 500
        return "Internal server error", 500

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=(), payment=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.is_secure:  # only meaningful (and only sent) over HTTPS
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")  # never cache API data
        return response

    return app
