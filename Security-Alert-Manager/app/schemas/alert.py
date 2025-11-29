from pydantic import BaseModel
from typing import Optional

class ChatRequest(BaseModel):
    question: str
    context_alert_id: Optional[int] = None