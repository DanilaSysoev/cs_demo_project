from typing import Any

import bleach
from fastapi import FastAPI, Request, Response
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response: Response = await call_next(request)
    policy = (
        "default-src 'self' https://cdn.jsdelivr.net; ",
        "script-src 'self' https://cdn.jsdelivr.net; ",
        "style-src 'self' https://cdn.jsdelivr.net; ",
        "img-src 'self' data:; ",
    )

    response.headers["Content-Security-Policy"] = "".join(policy)
    return response


@app.get("/")
def index(request: Request, name: str = "Guest") -> Any:
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"

    clear_name = bleach.clean(
        name,
        tags=["strong", "i"],
        attributes={"strong": ["class"]},
        strip=True,
    )
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "name": clear_name},
        headers={"Content-Security-Policy": csp},
    )


@app.get("/unsafe")
def index_unsafe(request: Request, name: str = "Guest") -> Any:
    csp = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "name": name},
        headers={"Content-Security-Policy": csp},
    )
