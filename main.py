import os
import uuid
from io import BytesIO
from typing import Annotated, Any
from urllib.parse import quote

import bleach
import filetype  # type: ignore
from cryptography.fernet import Fernet
from dotenv import load_dotenv  # type: ignore
from fastapi import Depends, FastAPI, Request, Response, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.responses import StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette import status
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

if os.getenv("SECRET_KEY") is None:
    raise ValueError("SECRET_KEY environment variable is not set")

app = FastAPI()
templates = Jinja2Templates(directory="templates")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY"),  # type: ignore
    https_only=True,
)


users = [
    {"username": "admin", "role": "admin"},
    {"username": "Danila", "role": "user"},
    {"username": "Alice", "role": "user"},
    {"username": "Guest", "role": "guest"},
]

files = [
    {
        "id": 1,
        "local_name": "file1.txt",
        "src_name": "file1.txt",
        "owner": "Danila",
        "mime": "plain/text",
        "is_secret": False,
    },
    {
        "id": 2,
        "local_name": "file2.txt",
        "src_name": "file2.txt",
        "owner": "Alice",
        "mime": "plain/text",
        "is_secret": False,
    },
]


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response: Response = await call_next(request)
    policy = (
        "default-src 'self' https://cdn.jsdelivr.net; ",
        "script-src 'self' https://cdn.jsdelivr.net 'sha256-QOOQu4W1oxGqd2nbXbxiA1Di6OHQOLQD+o+G9oWL8YY='; ",
        "style-src 'self' https://cdn.jsdelivr.net; ",
        "img-src 'self' https://fastapi.tiangolo.com data:",
    )

    response.headers["Content-Security-Policy"] = "".join(policy)
    return response


@app.post("/set-session")
def set_session(request: Request, name: str) -> Any:
    if name not in [u["username"] for u in users]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username"
        )
    request.session["name"] = name
    return {"message": "Session set successfully"}


@app.get("/get-session")
def get_session(request: Request) -> Any:
    if "name" not in request.session:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Need to set session first",
        )
    name = request.session["name"]
    return {"name": name}


@app.get("/drop-session")
def drop_session(request: Request) -> Any:
    request.session.clear()
    return {"message": "Session cleared successfully"}


@app.get("/")
def index(request: Request, name: str = "Guest") -> Any:
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:"

    clear_name = bleach.clean(
        name,
        tags=["strong", "i"],
        attributes={"strong": ["class"]},
        strip=True,
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        {"request": request, "name": clear_name},
        headers={"Content-Security-Policy": csp},
    )


@app.get("/unsafe")
def index_unsafe(request: Request, name: str = "Guest") -> Any:
    csp = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:"

    return templates.TemplateResponse(
        request,
        "index.html",
        {"request": request, "name": name},
        headers={"Content-Security-Policy": csp},
    )


def current_user(request: Request) -> dict | None:
    return next(
        (
            u
            for u in users
            if u["username"] == request.session.get("name", None)
        ),
        None,
    )


@app.get("/file/{file_id}")
def get_file_safe(
    request: Request,
    file_id: int,
    user: Annotated[dict | None, Depends(current_user)],
) -> Any:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized"
        )
    file = next((f for f in files if f["id"] == file_id), None)
    if file is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )

    if user["role"] == "admin" or file["owner"] == user["username"]:
        with open(f"uploads/{file['name']}", "rb") as f:
            data = f.read()
            if file["is_secret"]:
                data = Fernet(os.getenv("FERNET_KEY", "").encode()).decrypt(
                    data
                )
            return StreamingResponse(
                content=BytesIO(data),
                status_code=status.HTTP_200_OK,
                headers={
                    "Content-Disposition": f"attachment; filename*=UTF-8''{quote(str(file['src_name']))}"
                },
                media_type=str(file["mime"]),
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden"
        )


def get_mime_of_file(file: UploadFile) -> str:
    if (
        file.filename
        and not file.filename.lower().endswith(".jpg")
        and not file.filename.lower().endswith(".jpeg")
        and not file.filename.lower().endswith(".pdf")
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .jpg or .pdf files are allowed",
        )

    head = file.file.read(128)
    file.file.seek(0)
    kind = filetype.guess(head)
    if kind is None or kind.mime not in ["image/jpeg", "application/pdf"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is not a valid JPEG image",
        )
    return str(kind.mime)


def check_file_size(file: UploadFile) -> None:
    limit = 5 * 1024 * 1024
    size = file.size or 0
    if size > limit:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds the 5MB limit",
        )


@app.post("/upload")
def upload_file(
    request: Request,
    file: UploadFile,
    user: Annotated[dict | None, Depends(current_user)],
    is_secret: bool = False,
) -> Any:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized"
        )
    check_file_size(file)
    mime = get_mime_of_file(file)

    name = uuid.uuid4()
    with open(f"uploads/{name}", "wb") as f:
        data = file.file.read()
        if is_secret:
            data = Fernet(os.getenv("FERNET_KEY", "").encode()).encrypt(data)
        f.write(data)
    files.append(
        {
            "id": len(files) + 1,
            "name": name,
            "src_name": file.filename or "",
            "owner": user["username"],
            "is_secret": is_secret,
            "mime": mime,
        }
    )
    return {"message": "File uploaded successfully"}
