import math

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from learn_auth.app.core.deps import get_db
from learn_auth.app.schemas.todos import (
    PaginatedTodoResponse,
    PaginationInfo,
    TodoCreate,
    TodoResponse,
    TodoUpdate,
)
from learn_auth.app.services.todos import (
    create_todo,
    delete_todo,
    get_all_completed_todo,
    get_todo,
    list_todos,
    restore_todo,
    soft_delete_todo,
    update_todo,
)

router = APIRouter()


# create a new TODO item
@router.post(
    "/",
    response_model=TodoResponse,
    status_code=201,
)
def create_todo_endpoint(
    todo: TodoCreate,
    session: Session = Depends(get_db),
):
    return create_todo(session, todo)


@router.get("/", response_model=PaginatedTodoResponse, status_code=200)
def list_todos_endpoint(
    session: Session = Depends(get_db),
    page: int = Query(default=1, ge=1, description="Page number, starting from 1"),
    limit: int = Query(default=10, ge=1, le=20, description="Items per page (max 20)"),
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
        description="Search todos by title keyword (case-insensitive).",
    ),
):
    todos, total = list_todos(session, page=page, limit=limit, q=q)
    total_pages = math.ceil(total / limit) if total else 0
    return PaginatedTodoResponse(
        data=[TodoResponse.model_validate(todo) for todo in todos],
        pagination=PaginationInfo(
            page=page,
            limit=limit,
            total_items=total,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_previous=page > 1,
        ),
    )


# get all completed TODO items
@router.get(
    "/completed",
    response_model=list[TodoResponse],
    status_code=200,
)
def get_completed_todo_endpoint(
    session: Session = Depends(get_db),
):
    todo_items = get_all_completed_todo(session)
    return todo_items


# get a TODO item by id
@router.get(
    "/{todo_id}",
    response_model=TodoResponse,
    status_code=200,
)
def get_todo_endpoint(
    todo_id: int,
    session: Session = Depends(get_db),
):
    todo_item = get_todo(session, todo_id)
    if not todo_item:
        raise HTTPException(
            status_code=404,
            detail=f"TODO item not found with id {todo_id}",
        )
    return todo_item


# update a TODO item by id
@router.put(
    "/{todo_id}",
    response_model=TodoResponse,
    status_code=200,
)
def update_todo_endpoint(
    todo_id: int,
    todo: TodoUpdate,
    session: Session = Depends(get_db),
):
    todo_item = update_todo(session, todo_id, todo)
    if not todo_item:
        raise HTTPException(
            status_code=404,
            detail=f"TODO item not found with id {todo_id}",
        )
    return todo_item


# delete a TODO item by id
@router.delete(
    "/{todo_id}",
    status_code=204,
)
def soft_delete_todo_endpoint(
    todo_id: int,
    session: Session = Depends(get_db),
):
    result = soft_delete_todo(session, todo_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"TODO item not found or already deleted with id {todo_id}",
        )
    return None


# hard delete a TODO item by id
@router.delete(
    "/{todo_id}/hard",
    status_code=204,
)
def hard_delete_todo_endpoint(
    todo_id: int,
    session: Session = Depends(get_db),
):
    result = delete_todo(session, todo_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"TODO item not found or not soft-deleted with id {todo_id}",
        )
    return None


# restore a soft-deleted TODO item by id
@router.post(
    "/{todo_id}/restore",
    response_model=TodoResponse,
    status_code=200,
)
def restore_todo_endpoint(
    todo_id: int,
    session: Session = Depends(get_db),
):
    todo_item = restore_todo(session, todo_id)
    if not todo_item:
        raise HTTPException(
            status_code=404,
            detail=f"TODO item not found or not deleted with id {todo_id}",
        )
    return todo_item
