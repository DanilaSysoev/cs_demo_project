from pydantic import BaseModel, Field, field_validator


class Author(BaseModel):
    name: str = Field(..., description="The name of the author")
    year_of_birth: int = Field(
        ..., ge=0, le=2023, description="The year the author was born"
    )

    @field_validator("name")
    @classmethod
    def name_validator(cls, value: str) -> str:
        if not value:
            raise ValueError("Author name cannot be empty")
        return value


class Book(BaseModel):
    title: str = Field(..., description="The title of the book")
    author: Author = Field(..., description="The author of the book")
