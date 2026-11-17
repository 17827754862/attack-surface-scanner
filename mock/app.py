from __future__ import annotations

import threading

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


app = FastAPI(title="Local authorized mock target")


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return "<h1>Local mock target</h1><a href='/swagger.json'>swagger</a>"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mock"}


@app.get("/swagger.json")
def swagger() -> JSONResponse:
    return JSONResponse(
        {
            "openapi": "3.0.0",
            "info": {"title": "Mock API", "version": "1.0.0"},
            "paths": {
                "/item": {
                    "get": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "query",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
    )


@app.get("/.git/config", response_class=PlainTextResponse)
def git_config() -> str:
    return "[core]\n\trepositoryformatversion = 0\n"


@app.get("/.env", response_class=PlainTextResponse)
def env_file() -> str:
    return "MOCK_TOKEN=not-a-real-secret\n"


@app.get("/item")
def item(request: Request) -> PlainTextResponse:
    value = request.query_params.get("id", "")
    if "'" in value:
        return PlainTextResponse(
            "SQL syntax error near ''1'''",
            status_code=500,
        )
    return PlainTextResponse(f"item={value}")


def run_secondary() -> None:
    uvicorn.run(app, host="0.0.0.0", port=6443, log_level="warning")


if __name__ == "__main__":
    threading.Thread(target=run_secondary, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=8000)
