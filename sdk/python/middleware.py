"""
Ethio-Cyber-Shield (ECS) — Framework Middlewares for Python.
Provides plug-and-play telemetry capture for Flask, FastAPI, and Django applications.
Automatically normalizes requests to ECS Event Contract v1.1 and queues to Transactional Outbox.
"""
import time
import uuid
import logging
from typing import Optional, Dict, Any, List
from sdk.python.ecs_client import CanonicalEventBuilder
from sdk.python.outbox import TransactionalOutbox

logger = logging.getLogger(__name__)

DEFAULT_AUTH_PATHS = [
    "/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/auth/signin",
    "/oauth/token",
]

DEFAULT_PAYMENT_PATHS = [
    "/transfer",
    "/api/transfer",
    "/api/v1/transfer",
    "/pay",
    "/api/payment",
    "/api/v1/payment",
    "/api/remittance",
]


class ECSFlaskMiddleware:
    """
    Flask Extension / Middleware to capture security telemetry.
    Hooks into request lifecycle and enqueues Canonical Event v1.1 telemetry asynchronously.
    """

    def __init__(
        self,
        app=None,
        client=None,
        outbox: Optional[TransactionalOutbox] = None,
        source_system: str = "flask-app",
        auth_paths: Optional[List[str]] = None,
        payment_paths: Optional[List[str]] = None,
    ):
        self.client = client
        self.outbox = outbox or (TransactionalOutbox(client=client) if client else None)
        self.source_system = source_system
        self.auth_paths = auth_paths or DEFAULT_AUTH_PATHS
        self.payment_paths = payment_paths or DEFAULT_PAYMENT_PATHS

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        from flask import request

        @app.before_request
        def _before_request():
            request._ecs_start_time = time.time()

        @app.after_request
        def _after_request(response):
            try:
                self._capture_telemetry(request, response)
            except Exception as e:
                logger.debug(f"ECS Flask telemetry capture warning: {e}")
            return response

    def _capture_telemetry(self, req, resp):
        if not self.outbox:
            return

        path = req.path
        method = req.method.upper()
        status_code = resp.status_code

        # Determine if this route is relevant for security/fraud telemetry
        is_auth = any(path.rstrip("/").endswith(p.rstrip("/")) for p in self.auth_paths)
        is_payment = any(path.rstrip("/").endswith(p.rstrip("/")) for p in self.payment_paths)
        is_denied = status_code in (401, 403)

        if not (is_auth or is_payment or is_denied):
            return

        # Determine event type & result
        if is_auth:
            if status_code in (200, 201):
                event_type = "auth.login.succeeded"
                result = "SUCCESS"
            else:
                event_type = "auth.login.failed"
                result = "FAILURE"
        elif is_denied:
            event_type = "authz.denied"
            result = "DENIED"
        elif is_payment:
            event_type = "transaction.transfer.created"
            result = "SUCCESS" if status_code < 400 else "FAILURE"
        else:
            event_type = "api.request"
            result = "SUCCESS" if status_code < 400 else "FAILURE"

        # Client IP (support X-Forwarded-For)
        ip = req.headers.get("X-Forwarded-For", req.remote_addr)
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        # Build Canonical Event v1.1
        event = CanonicalEventBuilder.build(
            event_type=event_type,
            result=result,
            source_system=self.source_system,
            endpoint=path,
            source_ip=ip,
            channel="web",
            attributes={
                "http_method": method,
                "http_status": status_code,
                "user_agent": req.headers.get("User-Agent", "unknown"),
            }
        )

        self.outbox.enqueue(event)


class ECSFastAPIMiddleware:
    """
    ASGI Middleware for FastAPI / Starlette applications.
    Asynchronously logs security events into Transactional Outbox.
    """

    def __init__(
        self,
        app,
        client=None,
        outbox: Optional[TransactionalOutbox] = None,
        source_system: str = "fastapi-app",
        auth_paths: Optional[List[str]] = None,
    ):
        self.app = app
        self.client = client
        self.outbox = outbox or (TransactionalOutbox(client=client) if client else None)
        self.source_system = source_system
        self.auth_paths = auth_paths or DEFAULT_AUTH_PATHS

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.outbox:
            await self.app(scope, receive, send)
            return

        status_code = 200

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            path = scope.get("path", "")
            is_auth = any(path.rstrip("/").endswith(p.rstrip("/")) for p in self.auth_paths)
            if is_auth or status_code in (401, 403):
                result = "SUCCESS" if status_code < 400 else "FAILURE"
                event_type = "auth.login.succeeded" if result == "SUCCESS" else "auth.login.failed"
                client_ip = scope.get("client", ["127.0.0.1"])[0]

                event = CanonicalEventBuilder.build(
                    event_type=event_type,
                    result=result,
                    source_system=self.source_system,
                    endpoint=path,
                    source_ip=client_ip,
                    channel="api",
                    attributes={"http_status": status_code}
                )
                self.outbox.enqueue(event)


class ECSDjangoMiddleware:
    """
    Django HTTP Middleware to record security telemetry into ECS Outbox.
    Add 'sdk.python.middleware.ECSDjangoMiddleware' to MIDDLEWARE in settings.py.
    """

    def __init__(self, get_response, outbox: Optional[TransactionalOutbox] = None):
        self.get_response = get_response
        self.outbox = outbox

    def __call__(self, request):
        response = self.get_response(request)

        if self.outbox:
            try:
                path = request.path
                status_code = response.status_code
                if status_code in (401, 403) or "/login" in path:
                    result = "SUCCESS" if status_code < 400 else "FAILURE"
                    event = CanonicalEventBuilder.build(
                        event_type="auth.login.succeeded" if result == "SUCCESS" else "auth.login.failed",
                        result=result,
                        source_system="django-app",
                        endpoint=path,
                        source_ip=request.META.get("REMOTE_ADDR"),
                        channel="web",
                        attributes={"http_status": status_code}
                    )
                    self.outbox.enqueue(event)
            except Exception as e:
                logger.debug(f"Django ECS middleware warning: {e}")

        return response
