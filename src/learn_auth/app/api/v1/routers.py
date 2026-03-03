from fastapi import APIRouter

from learn_auth.app.api.v1.endpoints.todos import router as todo_router

router = APIRouter()
router.include_router(todo_router, prefix="/todos", tags=["todos"])
