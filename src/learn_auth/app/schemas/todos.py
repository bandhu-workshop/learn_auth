from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TodoCreate(BaseModel):
    title: str
    description: str | None = None
    is_completed: bool = False


class TodoUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    is_completed: bool | None = None


class TodoResponse(BaseModel):
    id: int
    title: str
    description: str | None = None
    is_completed: bool
    created_at: datetime
    updated_at: datetime | None = None
    deleted_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class PaginationInfo(BaseModel):
    page: int
    limit: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class PaginatedTodoResponse(BaseModel):
    data: list[TodoResponse]
    pagination: PaginationInfo
