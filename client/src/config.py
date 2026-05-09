import os

SERVER_URL = os.environ.get("UPDATE_SERVER_URL", "http://127.0.0.1:8000")
LOCAL_VERSION = os.environ.get("UPDATE_LOCAL_VERSION", "1.0.0")
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("UPDATE_REQUEST_TIMEOUT", "10"))
