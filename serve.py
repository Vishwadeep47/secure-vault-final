"""Run SecureVault with Waitress, a production-grade server that also works on Windows.

    python serve.py

Use this instead of run.py for demos and deployment. Flask's built-in server (run.py)
is for development only.

Optional settings (environment variables):
    VAULT_HOST   address to listen on   (default 127.0.0.1 = this computer only)
    VAULT_PORT   port                   (default 5000)

For HTTPS, put a reverse proxy (Caddy or nginx) in front of this server.
See docs/hardening.md.
"""
import os

from waitress import serve

from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("VAULT_HOST", "127.0.0.1")
    port = int(os.environ.get("VAULT_PORT", "5000"))
    print(f"SecureVault is running on http://{host}:{port}  (Waitress). Press Ctrl+C to stop.", flush=True)
    serve(
        app,
        host=host,
        port=port,
        threads=4,
        max_request_body_size=11 * 1024 * 1024,  # a little above the 10 MB image limit
        ident="SecureVault",                      # hides the server software and version
    )
