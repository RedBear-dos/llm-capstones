from fastapi import APIRouter, BackgroundTasks, Depends, Request
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.alert import Alert
from app.services.log_parser import LogParser
from app.services.llm_service import LLMService

router = APIRouter()

@router.post("/")
async def receive_webhook(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        parsed = LogParser.parse(data)
        
        if db.query(Alert).filter(Alert.shuffle_id == parsed["shuffle_id"]).first():
            return {"status": "skipped", "msg": "Duplicate"}

        new_alert = Alert(**parsed)
        new_alert.ai_analysis = "Đang chờ AI..."
        
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        
        background_tasks.add_task(LLMService.analyze_alert, new_alert.id, db)
        
        return {"status": "success", "id": new_alert.id}
    except Exception as e:
        return {"status": "error", "detail": str(e)}