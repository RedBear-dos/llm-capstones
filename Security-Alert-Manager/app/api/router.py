from fastapi import APIRouter
from app.api.endpoints import webhooks, alerts, chatbot

api_router = APIRouter()

api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(chatbot.router, prefix="/chatbot", tags=["chatbot"])