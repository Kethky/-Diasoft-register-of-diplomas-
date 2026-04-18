from pathlib import Path

from flask import Flask, jsonify, request

from .config import Config
from .db import create_security_tables, update_db_schema
from .extensions import limiter
from .services.security_service import generate_csrf_token


def create_app() -> Flask:
    base_dir = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(base_dir / "templates"),
        static_folder=str(base_dir / "static"),
        static_url_path="/static",
    )
    app.config.from_object(Config)

    limiter.init_app(app)

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf_token()}

    @app.errorhandler(429)
    def ratelimit_handler(error):
        from .services.security_service import log_security_event

        log_security_event(request.remote_addr, request.endpoint)
        return jsonify(
            {
                "error": "Слишком много запросов",
                "message": str(error.description),
                "retry_after": 60,
            }
        ), 429

    with app.app_context():
        create_security_tables()
        update_db_schema()

    from .routes.pages import bp as pages_bp
    from .routes.auth import bp as auth_bp
    from .routes.university import bp as university_bp
    from .routes.public import bp as public_bp
    from .routes.qr import bp as qr_bp
    from .routes.hr import bp as hr_bp
    from .routes.admin import bp as admin_bp

    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(university_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(qr_bp)
    app.register_blueprint(hr_bp)
    app.register_blueprint(admin_bp)

    return app
