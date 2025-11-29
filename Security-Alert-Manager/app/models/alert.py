from sqlalchemy import Column, Integer, String, Text, JSON, DateTime
from datetime import datetime
from app.db.base import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    shuffle_id = Column(String(255), unique=True, nullable=True)
    rule_id = Column(String(50))
    timestamp = Column(DateTime, default=datetime.now)
    title = Column(Text)
    description = Column(Text)
    severity = Column(Integer)
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True)
    attack_type = Column(String(100))
    full_log = Column(JSON)
    ai_analysis = Column(Text, nullable=True)
    mitre_tactic = Column(Text, nullable=True)