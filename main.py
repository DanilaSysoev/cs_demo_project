from typing import Any

from fastapi import FastAPI

from models import Book

app = FastAPI()


@app.post("/")
def index(book: Book) -> dict[str, Any]:
    return {"message": "book received", "book": book}
