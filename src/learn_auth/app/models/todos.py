from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from learn_auth.app.core.config import settings
from learn_auth.app.core.database import Base


class Todo(Base):
    """
    Model for a TODO.
    Note: The class name is singular (Todo) while the table name is plural (todos). This is a common convention in SQLAlchemy models.
    """

    __tablename__ = "todos"
    __table_args__ = {"schema": settings.SCHEMA}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    # Note: We use Text for description to allow for longer text, and we set nullable=True to make it optional.
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        onupdate=func.now(),
        nullable=True,
    )

    # soft delete support
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
