import uvicorn

from app import app
from config import HOST, PORT

if __name__ == "__main__":
    print(f"Starting Merkle Tree Transparency Log on http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)
