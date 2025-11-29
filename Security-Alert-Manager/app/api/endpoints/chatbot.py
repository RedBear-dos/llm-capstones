from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.alert import ChatRequest
from app.services.llm_service import LLMService

router = APIRouter()

@router.post("/")
def chatbot(req: ChatRequest, db: Session = Depends(get_db)):
    response = LLMService.chat(req.question, req.context_alert_id, db)
    return {"response": response}