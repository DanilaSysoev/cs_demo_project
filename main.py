import os
import shutil
import uuid
from typing import Annotated, Any

import bleach
import filetype  # type: ignore
from dotenv import load_dotenv  # type: ignore
from fastapi import Depends, FastAPI, Request, Response, UploadFile
from fastapi.exceptions import HTTPException
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
    },
    {
        "id": 2,
        "local_name": "file2.txt",
        "src_name": "file2.txt",
        "owner": "Alice",
    },
]


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response: Response = await call_next(request)
    policy = (
        "default-src 'self' https://cdn.jsdelivr.net; ",
        "script-src 'self' https://cdn.jsdelivr.net 'sha256-QOOQu4W1oxGqd2nbXbxiA1Di6OHQOLQD+o+G9oWL8YY='; ",
        "style-src 'self' https://cdn.jsdelivr.net; ",
        "img-src 'self' https://fastapi.tiangolo.com data:; ",
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
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"

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
    csp = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"

    return templates.TemplateResponse(
        request,
        "index.html",
        {"request": request, "name": name},
        headers={"Content-Security-Policy": csp},
    )


@app.get("/files/{file_id}")
def get_file(request: Request, file_id: int) -> Any:
    user = next(
        (
            u
            for u in users
            if u["username"] == request.session.get("name", None)
        ),
        None,
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized"
        )
    file = next((f for f in files if f["id"] == file_id), None)
    if file is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )
    return {"file": file}


def current_user(request: Request) -> dict | None:
    return next(
        (
            u
            for u in users
            if u["username"] == request.session.get("name", None)
        ),
        None,
    )


@app.get("/file-safe/{file_id}")
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
        return {"file": file}
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden"
        )


file_database: list[Any] = []


@app.post("/upload")
def upload_file(request: Request, file: UploadFile) -> Any:
    name = uuid.uuid4()
    with open(f"uploads/{name}", "wb") as f:
        shutil.copyfileobj(file.file, f)
    file_database.append(
        {"id": len(file_database) + 1, "name": name, "src_name": file.filename}
    )
    return {"message": "File uploaded successfully"}


@app.post("/upload-jpg")
def upload_jpg(request: Request, file: UploadFile) -> Any:
    if (
        file.filename
        and not file.filename.lower().endswith(".jpg")
        and not file.filename.lower().endswith(".jpeg")
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .jpg files are allowed",
        )

    head = file.file.read(128)
    kind = filetype.guess(head)
    if kind is None or kind.mime not in ["image/jpeg"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is not a valid JPEG image",
        )

    name = uuid.uuid4()
    with open(f"uploads/{name}", "wb") as f:
        shutil.copyfileobj(file.file, f)
    file_database.append(
        {"id": len(file_database) + 1, "name": name, "src_name": file.filename}
    )
    return {"message": "File uploaded successfully"}


@app.post("/upload-big-file")
def upload_big_file(request: Request, file: UploadFile) -> Any:
    limit = 1024 * 1024 * 1024  # 1GB
    # if file.size > limit:
    #     raise HTTPException(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         detail="File size exceeds the 1GB limit",
    #     )

    cur_size = 0
    chunk_size = 1024  # 1KB
    name = uuid.uuid4()
    with open(f"uploads/{name}", "wb") as f:
        while True:
            chunk = file.file.read(chunk_size)
            if not chunk:
                break
            cur_size += len(chunk)
            if cur_size > limit:
                os.remove(f"uploads/{name}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File size exceeds the 1GB limit",
                )
            f.write(chunk)

    file_database.append(
        {"id": len(file_database) + 1, "name": name, "src_name": file.filename}
    )
    return {"message": "File uploaded successfully"}
