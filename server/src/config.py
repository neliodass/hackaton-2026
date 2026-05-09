import os

HOST = os.environ.get("UPDATE_SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("UPDATE_SERVER_PORT", "8000"))
