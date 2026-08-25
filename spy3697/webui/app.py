from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from .. import orchestrator as orc
from ..config import load_config
from ..guardrails import AuthorizationError
from ..llm import build_llm

HERE = Path(__file__).parent


class ConnectionLog:
    """Bridges synchronous orchestrator log callbacks into an asyncio queue
    consumed by the websocket handler."""
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.loop = asyncio.get_event_loop()

    def __call__(self, msg: str):
        self.loop.call_soon_threadsafe(self.queue.put_nowait, msg)


def build_app(config_path: str = "config.yaml") -> FastAPI:
    app = FastAPI(title="SPY-3697")
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (HERE / "templates" / "index.html").read_text()

    @app.get("/api/config-summary")
    def config_summary():
        cfg = load_config(config_path)
        return {
            "llm_provider": cfg.llm.provider,
            "llm_model": cfg.llm.model,
            "authorized_targets": cfg.authorized_targets,
        }

    @app.websocket("/ws/run")
    async def ws_run(ws: WebSocket):
        await ws.accept()
        try:
            init = await ws.receive_json()
            target = init["target"]
            goal = init.get("goal", "Check this target for common vulnerabilities")
            confirmed = bool(init.get("i_confirm_authorization", False))

            try:
                cfg = load_config(config_path)
                llm = build_llm(cfg.llm)
            except Exception as e:  # noqa: BLE001
                await ws.send_text(f"[error] failed to start: {e}")
                await ws.send_text("[[DONE]]")
                return

            logger = ConnectionLog()

            def worker():
                try:
                    orc.run_full_pipeline(cfg, llm, target, goal, confirmed, log=logger)
                except AuthorizationError as e:
                    logger(f"[auth-error] {e}")
                except Exception as e:  # noqa: BLE001
                    logger(f"[error] {e!r}")
                finally:
                    logger("[[DONE]]")

            t = threading.Thread(target=worker, daemon=True)
            t.start()

            while True:
                msg = await logger.queue.get()
                await ws.send_text(msg)
                if msg == "[[DONE]]":
                    break
        except WebSocketDisconnect:
            pass

    @app.get("/api/report/{target}/{run_id}")
    def get_report(target: str, run_id: str):
        cfg = load_config(config_path)
        path = cfg.workspace_dir / target.replace("/", "_") / run_id / "report.md"
        if not path.exists():
            return {"error": "report not found"}
        return FileResponse(path)

    return app
