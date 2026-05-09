import logging
from time import perf_counter

from fastapi import FastAPI, Request

from api.routes import router

logger = logging.getLogger("update-server")

app = FastAPI(title="Secure Software Update Server", version="0.1.0")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = perf_counter()
    logger.info("request_started method=%s path=%s", request.method, request.url.path)
    response = await call_next(request)
    duration_ms = (perf_counter() - start) * 1000
    logger.info(
        "request_finished method=%s path=%s status=%s duration_ms=%.2f",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


app.include_router(router)
