from app import create_app

app = create_app()

if __name__ == "__main__":
    debug_mode = app.config.get("FLASK_DEBUG", False)
    host = "127.0.0.1" if debug_mode else "0.0.0.0"
    app.run(debug=debug_mode, host=host, port=5000)
