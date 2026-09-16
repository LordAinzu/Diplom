"""HTTP boundary: local prototype, one coordinator worker per database."""
import asyncio
import secrets
import httpx
from contextlib import asynccontextmanager, suppress
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from cryptography.exceptions import InvalidSignature, InvalidTag
from .coordinator import Coordinator
from .signer import Signer


def common(app):
    @app.exception_handler(httpx.HTTPError)
    async def upstream_error(request, exc):
        return JSONResponse(status_code=503, content={"detail": "signer unavailable; retry the same session"})

    @app.exception_handler(ValueError)
    @app.exception_handler(KeyError)
    @app.exception_handler(TypeError)
    @app.exception_handler(InvalidSignature)
    @app.exception_handler(InvalidTag)
    async def protocol_error(request, exc):
        # No payloads or secrets in errors or logs.
        return JSONResponse(status_code=409, content={"detail": "request rejected: invalid input or protocol state"})

    @app.middleware("http")
    async def bounded_body(request, call_next):
        # Bound actual streamed size, including requests without Content-Length.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2_000_000:
                return JSONResponse(status_code=413, content={"detail": "request too large"})
        request._body = bytes(body)
        return await call_next(request)

    @app.get("/health")
    def health():
        return {"ok": True}


def signer_app(config, database):
    signer = Signer(config, database)
    app = FastAPI(title="SB+ signer")
    common(app)
    app.state.service = signer

    @app.post("/rpc")
    def rpc(packet: dict):
        return signer.rpc(packet)

    return app


def coordinator_app(config, database, transport=None):
    coord = Coordinator(config, database, transport)

    @asynccontextmanager
    async def lifespan(app):
        async def retry():
            while True:
                await coord.flush()
                await asyncio.sleep(5)
        task = asyncio.create_task(retry())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="SB+ coordinator", lifespan=lifespan)
    common(app)
    app.state.service = coord

    def auth(request, admin=False):
        expected = config["admin_token" if admin else "client_token"]
        if not secrets.compare_digest(request.headers.get("authorization", ""), "Bearer "+expected):
            raise HTTPException(401, "authentication required")

    @app.get("/group")
    def group():
        return coord.parameters()

    @app.post("/admin/dkg")
    async def dkg(request: Request):
        auth(request, True)
        return await coord.dkg()

    @app.post("/sessions")
    async def create(request: Request, payload: dict):
        auth(request)
        return await coord.create(payload)

    @app.get("/sessions/{sid}")
    def get_session(sid: str, request: Request):
        auth(request)
        return coord.session(sid)

    @app.post("/sessions/{sid}/rounds/{number}")
    async def round(sid: str, number: int, payload: dict, request: Request):
        auth(request)
        return await coord.round(sid, number, payload)

    return app
