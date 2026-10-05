"""How reset tokens reach the user.

DEVELOPMENT version: prints the token in the server console. There is no email
address on accounts yet, so this stands in for email/SMS.

In production replace the body of send_reset_token() with a real email or SMS
sender. Nothing else in the project needs to change. Never log tokens in production.
"""


def send_reset_token(username, token):
    print(f"[password reset] user={username} token={token}", flush=True)
