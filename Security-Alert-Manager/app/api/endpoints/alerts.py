from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db.session import get_db
from app.models.alert import Alert

router = APIRouter()

@router.get("/")
def get_alerts(db: Session = Depends(get_db), limit: int = 50):
    return db.query(Alert).order_by(desc(Alert.timestamp)).limit(limit).all()

@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Not found")
    return alert