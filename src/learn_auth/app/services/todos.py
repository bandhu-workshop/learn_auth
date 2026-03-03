from datetime import datetime, timezone

from sqlalchemy.orm import Session

from learn_auth.app.models.todos import Todo
from learn_auth.app.schemas.todos import TodoCreate, TodoUpdate


def create_todo(session: Session, todo: TodoCreate) -> Todo:
    # create a new todo item
    todo_item = Todo(**todo.model_dump())
    session.add(todo_item)
    session.commit()
    session.refresh(todo_item)
    return todo_item


def list_todos(
    session: Session,
    include_deleted: bool = False,
    page: int = 1,
    limit: int = 10,
    q: str | None = None,
) -> tuple[list[Todo], int]:
    # list paginated todo items — returns (items, total_count)
    # total_count is the full count matching the filter (ignoring pagination)
    # so the API layer can compute total_pages, has_next, has_previous
    query = session.query(Todo)
    if not include_deleted:
        query = query.filter(Todo.deleted_at.is_(None))

    # title keyword search — case-insensitive substring match
    # ilike = case-insensitive LIKE; works on SQLite and PostgreSQL
    if q:
        query = query.filter(Todo.title.ilike(f"%{q.strip()}%"))

    total_count = query.count()
    items = (
        query.order_by(Todo.created_at.desc(), Todo.id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )
    return items, total_count


def get_todo(session: Session, todo_id: int) -> Todo | None:
    # get a todo item by id
    # instead of
    #   `session.query(Todo).filter(Todo.id == todo_id).first()`,
    # we use
    #   `session.get(Todo, todo_id)`
    # which is more efficient and cleaner.
    #   - Cleaner
    #   - Faster
    #   - Primary-key optimized
    #   - More modern (SQLAlchemy 1.4+ / 2.0 style)

    # todo_item = session.get(Todo, todo_id)
    # if todo_item and todo_item.deleted_at is None:
    #     return todo_item
    # return None
    return (
        session.query(Todo)
        .filter(Todo.id == todo_id, Todo.deleted_at.is_(None))
        .first()
    )


def get_all_completed_todo(session: Session) -> list[Todo]:
    # get all completed todo items
    return (
        session.query(Todo)
        .filter(
            Todo.deleted_at.is_(None),
            Todo.is_completed.is_(True),
        )
        .all()
    )


def update_todo(session: Session, todo_id: int, todo: TodoUpdate) -> Todo | None:
    # update a todo item by id
    todo_item = session.get(Todo, todo_id)
    if not todo_item or todo_item.deleted_at is not None:
        return None

    for key, value in todo.model_dump(exclude_unset=True).items():
        setattr(todo_item, key, value)

    session.commit()
    session.refresh(todo_item)
    return todo_item


def delete_todo(session: Session, todo_id: int) -> bool:
    # delete a todo item by id
    todo_item = session.get(Todo, todo_id)
    if not todo_item:
        return False

    session.delete(todo_item)
    session.commit()
    return True


def soft_delete_todo(session: Session, todo_id: int) -> bool:
    # soft delete a todo item by id
    todo_item = (
        session.query(Todo)
        .filter(Todo.id == todo_id, Todo.deleted_at.is_(None))
        .first()
    )
    if not todo_item:
        return False

    todo_item.deleted_at = datetime.now(timezone.utc)
    session.commit()
    return True


def restore_todo(session: Session, todo_id: int) -> Todo | None:
    # restore a soft-deleted todo item by id
    todo_item = (
        session.query(Todo)
        .filter(Todo.id == todo_id, Todo.deleted_at.isnot(None))
        .first()
    )
    if not todo_item:
        return None

    todo_item.deleted_at = None
    session.commit()
    session.refresh(todo_item)
    return todo_item
