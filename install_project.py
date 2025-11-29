import os
import sys

# Tên thư mục dự án
BASE_DIR = "Security-Alert-Manager"

# Nội dung của tất cả các file trong dự án
project_files = {
    # ---------------------------------------------------------
    # 1. CẤU HÌNH & DATABASE
    # ---------------------------------------------------------
    "app/__init__.py": "",
    
    "app/core/__init__.py": "",
    "app/core/config.py": """
import os

class Settings:
    PROJECT_NAME: str = "Security Alert Manager"
    VERSION: str = "1.0.0"
    
    # --- DATABASE CONFIG ---
    # Đổi thành True nếu bạn muốn dùng MySQL (Production)
    USE_MYSQL: bool = False  
    
    MYSQL_USER: str = "root"
    MYSQL_PASSWORD: str = ""
    MYSQL_SERVER: str = "localhost"
    MYSQL_PORT: str = "3306"
    MYSQL_DB: str = "security_db"
    
    # --- AI CONFIG ---
    OLLAMA_URL: str = "http://localhost:11434/api/generate"
    # Model AI (Hãy đảm bảo bạn đã chạy 'ollama run qwen2.5:1.5b')
    AI_MODEL: str = "qwen2.5:1.5b" 

    @property
    def DATABASE_URL(self) -> str:
        if self.USE_MYSQL:
            return f"mysql+pymysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}@{self.MYSQL_SERVER}:{self.MYSQL_PORT}/{self.MYSQL_DB}"
        # Mặc định dùng SQLite cho dễ chạy
        return "sqlite:///./security_db.sqlite"

settings = Settings()
""",

    "app/db/__init__.py": "",
    "app/db/base.py": """
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
""",
    "app/db/session.py": """
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Nếu dùng SQLite thì cần check_same_thread=False
connect_args = {"check_same_thread": False} if not settings.USE_MYSQL else {}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
""",

    # ---------------------------------------------------------
    # 2. MODELS & SCHEMAS
    # ---------------------------------------------------------
    "app/models/__init__.py": "",
    "app/models/alert.py": """
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
""",

    "app/schemas/__init__.py": "",
    "app/schemas/alert.py": """
from pydantic import BaseModel
from typing import Optional

class ChatRequest(BaseModel):
    question: str
    context_alert_id: Optional[int] = None
""",

    # ---------------------------------------------------------
    # 3. SERVICES (LOGIC XỬ LÝ)
    # ---------------------------------------------------------
    "app/services/__init__.py": "",
    "app/services/log_parser.py": """
from typing import Dict, Any
from datetime import datetime

class LogParser:
    @staticmethod
    def parse(data: Dict[str, Any]) -> Dict[str, Any]:
        parsed = {
            "shuffle_id": str(data.get("id", datetime.now().timestamp())),
            "rule_id": str(data.get("rule_id", "000")),
            "timestamp": datetime.now(),
            "title": data.get("title", "Unknown Alert"),
            "description": data.get("text", str(data)),
            "severity": int(data.get("severity", 1)),
            "full_log": data,
            "source_ip": "N/A",
            "attack_type": "Security Alert",
            "mitre_tactic": "Unknown"
        }

        # Xử lý timestamp
        ts_str = data.get("timestamp")
        if ts_str:
            try:
                parsed["timestamp"] = datetime.fromisoformat(ts_str.replace("+0700", "+07:00"))
            except: pass

        # Lấy thông tin chi tiết
        all_fields = data.get("all_fields", {})
        rule_info = all_fields.get("rule", {})
        mitre = rule_info.get("mitre", {})
        
        if mitre:
            parsed["mitre_tactic"] = f"{mitre.get('id', [])} - {mitre.get('tactic', [])}"

        # Logic phân loại tấn công
        rule_id = parsed["rule_id"]
        log_data = all_fields.get("data", {})
        title_lower = parsed["title"].lower()

        if rule_id == "5551" or "failed login" in title_lower:
            parsed["attack_type"] = "SSH Brute-Force"
            parsed["source_ip"] = log_data.get("srcip", "N/A")
        elif rule_id == "31103" or "sql injection" in title_lower:
            parsed["attack_type"] = "Web Attack (SQLi/XSS)"
            parsed["source_ip"] = log_data.get("srcip", "N/A")
        elif rule_id == "100501" or "file modification" in title_lower:
            parsed["attack_type"] = "Suspicious File Creation"
        elif rule_id == "100210" or "audit" in title_lower:
            parsed["attack_type"] = "Privilege Escalation"
            audit = log_data.get("audit", {})
            parsed["source_ip"] = f"User: {audit.get('uid', 'local')}"
        elif rule_id == "86601" or "nmap" in title_lower:
            parsed["attack_type"] = "Reconnaissance (Scan)"
            parsed["source_ip"] = log_data.get("src_ip", "N/A")
        else:
            parsed["source_ip"] = log_data.get("srcip") or log_data.get("src_ip") or "N/A"

        return parsed
""",

    "app/services/llm_service.py": """
import requests
import logging
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.alert import Alert

logger = logging.getLogger(__name__)

class LLMService:
    @staticmethod
    def mock_response(prompt_type: str) -> str:
        if prompt_type == "analysis":
            return "**⚠️ AI Offline:**\\nKhông kết nối được Ollama. Phân tích giả lập:\\n1. **Hành vi:** Bất thường.\\n2. **Rủi ro:** Trung bình.\\n3. **Khuyến nghị:** Kiểm tra log."
        return "Tôi đang ở chế độ Offline. Vui lòng bật Ollama để chat."

    @staticmethod
    def analyze_alert(alert_id: int, db: Session):
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert: return

        prompt = f"Phân tích log: {alert.title}. Nội dung: {alert.description}. Trả lời ngắn gọn 3 ý: Tóm tắt, Mức độ, Khuyến nghị."
        
        try:
            res = requests.post(settings.OLLAMA_URL, json={
                "model": settings.AI_MODEL, "prompt": prompt, "stream": False
            }, timeout=30)
            
            if res.status_code == 200:
                alert.ai_analysis = res.json().get("response", "")
            else:
                alert.ai_analysis = LLMService.mock_response("analysis")
        except Exception as e:
            logger.warning(f"Ollama Error: {e}")
            alert.ai_analysis = LLMService.mock_response("analysis")
        
        db.commit()

    @staticmethod
    def chat(question: str, context_alert_id: int = None, db: Session = None) -> str:
        context = ""
        if context_alert_id and db:
            alert = db.query(Alert).filter(Alert.id == context_alert_id).first()
            if alert:
                context = f"\\n[Context: Alert ID {alert.id} - {alert.attack_type}]"

        prompt = f"Q: {question}{context}\\nA:"
        
        try:
            res = requests.post(settings.OLLAMA_URL, json={
                "model": settings.AI_MODEL, "prompt": prompt, "stream": False
            }, timeout=10)
            if res.status_code == 200:
                return res.json().get("response")
        except:
            pass
        return LLMService.mock_response("chat")
""",

    # ---------------------------------------------------------
    # 4. API ENDPOINTS
    # ---------------------------------------------------------
    "app/api/__init__.py": "",
    "app/api/endpoints/__init__.py": "",
    
    "app/api/endpoints/webhooks.py": """
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
""",

    "app/api/endpoints/alerts.py": """
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
""",

    "app/api/endpoints/chatbot.py": """
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
""",

    "app/api/router.py": """
from fastapi import APIRouter
from app.api.endpoints import webhooks, alerts, chatbot

api_router = APIRouter()

api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(chatbot.router, prefix="/chatbot", tags=["chatbot"])
""",

    # ---------------------------------------------------------
    # 5. MAIN ENTRY POINT
    # ---------------------------------------------------------
    "app/main.py": """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app.api.router import api_router

# Tạo bảng Database tự động
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION
)

# CORS (Cho phép mọi nguồn)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    print(f"🚀 {settings.PROJECT_NAME} running on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
""",

    # ---------------------------------------------------------
    # 6. FRONTEND & DOCS
    # ---------------------------------------------------------
    "frontend/index.html": """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert Manager (Pro)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
        .glass-panel { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .chat-msg { margin-bottom: 12px; padding: 12px; border-radius: 8px; max-width: 85%; line-height: 1.5; font-size: 0.95rem; }
        .chat-user { background: #3b82f6; color: white; margin-left: auto; border-top-right-radius: 0; }
        .chat-bot { background: #334155; color: #e2e8f0; border-top-left-radius: 0; border: 1px solid #475569; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
        .demo-badge { position: fixed; bottom: 10px; right: 10px; background: #eab308; color: black; padding: 5px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; opacity: 0.9; z-index: 1000; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .hidden { display: none; }
    </style>
</head>
<body class="h-screen flex flex-col overflow-hidden">
    <header class="bg-slate-900 border-b border-slate-700 p-4 flex justify-between items-center shadow-lg z-10">
        <div class="flex items-center gap-3">
            <div class="bg-slate-800 p-2 rounded-lg border border-slate-600"><i class="fa-solid fa-shield-halved text-2xl text-green-500"></i></div>
            <div><h1 class="text-xl font-bold tracking-wider text-white">SEC-ALERT MANAGER</h1><p class="text-xs text-slate-400 uppercase tracking-widest">AI-Powered SOC Dashboard</p></div>
        </div>
        <div class="flex gap-4">
            <button onclick="fetchAlerts()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm transition font-medium flex items-center shadow-lg"><i class="fa-solid fa-rotate mr-2"></i> Refresh</button>
            <div id="statusIndicator" class="text-green-400 text-sm flex items-center gap-2 border border-green-900 bg-green-900/20 px-3 rounded-full transition-all duration-300"><div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div> System Online</div>
        </div>
    </header>

    <div class="flex flex-1 overflow-hidden relative">
        <main class="flex-1 p-6 overflow-y-auto flex flex-col">
            <h2 class="text-lg font-semibold mb-4 text-blue-300 flex items-center"><i class="fa-solid fa-list-ul mr-2"></i> Live Alerts Feed</h2>
            <div class="glass-panel rounded-xl overflow-hidden shadow-2xl flex-1 flex flex-col">
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead class="bg-slate-800 text-slate-400 uppercase text-xs font-bold tracking-wider"><tr><th class="p-4 border-b border-slate-700">Time</th><th class="p-4 border-b border-slate-700">Level</th><th class="p-4 border-b border-slate-700">Type</th><th class="p-4 border-b border-slate-700">IP</th><th class="p-4 border-b border-slate-700 w-10"></th></tr></thead>
                        <tbody id="alertTableBody" class="divide-y divide-slate-700 text-sm"><tr><td colspan="5" class="p-10 text-center text-slate-500 italic">Connecting...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </main>
        <aside class="w-[450px] bg-slate-900 border-l border-slate-700 flex flex-col shadow-2xl z-20">
            <div class="h-3/5 flex flex-col border-b border-slate-700 bg-slate-900">
                <div class="p-4 bg-slate-800/50 border-b border-slate-700 flex justify-between items-center backdrop-blur-sm"><h3 class="font-bold text-yellow-400 flex items-center"><i class="fa-solid fa-circle-info mr-2"></i> Detail</h3><span id="detailId" class="text-[10px] bg-slate-700 px-2 py-1 rounded text-slate-300 font-mono">ID: --</span></div>
                <div id="detailContent" class="flex-1 p-5 overflow-y-auto text-sm space-y-4"><div class="flex flex-col items-center justify-center h-full text-slate-600 opacity-60"><i class="fa-solid fa-magnifying-glass-chart text-5xl mb-3"></i><p>Select an alert</p></div></div>
            </div>
            <div class="h-2/5 flex flex-col bg-slate-800 relative">
                <div class="p-3 bg-slate-900 border-b border-slate-700 flex justify-between items-center shadow-sm"><h3 class="font-bold text-blue-400 flex items-center text-sm"><i class="fa-solid fa-robot mr-2"></i> AI Assistant</h3><button onclick="clearChat()" class="text-xs text-slate-500 hover:text-red-400 transition"><i class="fa-solid fa-trash-can"></i></button></div>
                <div id="chatHistory" class="flex-1 p-4 overflow-y-auto bg-slate-800/80"><div class="chat-msg chat-bot shadow-sm">Hello! I am your AI Security Assistant.</div></div>
                <div class="p-3 bg-slate-900 border-t border-slate-700"><form id="chatForm" class="flex gap-2 relative"><input type="text" id="chatInput" placeholder="Ask AI..." class="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500 transition shadow-inner"><button type="submit" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-white transition shadow-lg flex items-center justify-center min-w-[50px]"><i class="fa-solid fa-paper-plane"></i></button></form></div>
            </div>
        </aside>
    </div>
    <div id="demoBadge" class="demo-badge hidden flex items-center gap-2 ring-2 ring-yellow-600/50"><i class="fa-solid fa-triangle-exclamation"></i> DEMO MODE: OFFLINE</div>

    <script>
        const API_URL = "http://localhost:8000/api";
        let isDemoMode = false; let currentAlertId = null;
        const MOCK_ALERTS = [{ id: 101, timestamp: new Date().toISOString(), severity: 12, attack_type: "SSH Brute-Force", source_ip: "192.168.1.105", rule_id: "5551", title: "Multiple failed logins", full_log: {}, ai_analysis: "**Demo:** Detected SSH Brute Force. Recommend blocking IP." }];

        async function fetchAlerts() {
            try {
                const controller = new AbortController(); setTimeout(() => controller.abort(), 1500);
                const res = await fetch(`${API_URL}/alerts/`, { signal: controller.signal });
                const alerts = await res.json();
                renderTable(alerts);
                if (isDemoMode) { isDemoMode = false; document.getElementById('demoBadge').classList.add('hidden'); document.getElementById('statusIndicator').innerHTML = '<div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div> System Online'; }
            } catch (err) { activateDemoMode(); }
        }
        function activateDemoMode() { if(isDemoMode) return; isDemoMode = true; document.getElementById('demoBadge').classList.remove('hidden'); document.getElementById('statusIndicator').innerHTML = '<div class="w-2 h-2 bg-yellow-500 rounded-full"></div> Demo Mode'; renderTable(MOCK_ALERTS); }
        function renderTable(alerts) {
            const tbody = document.getElementById('alertTableBody'); tbody.innerHTML = '';
            alerts.forEach(a => {
                const tr = document.createElement('tr'); tr.className = "hover:bg-slate-700/50 cursor-pointer border-b border-slate-800 transition duration-150 group"; tr.onclick = () => loadDetail(a);
                let sevClass = "text-blue-400 font-medium"; let sevLabel = "Low";
                if(a.severity >= 5) { sevClass = "text-yellow-400 font-bold"; sevLabel = "Medium"; }
                if(a.severity >= 10) { sevClass = "text-red-500 font-extrabold animate-pulse"; sevLabel = "CRITICAL"; }
                tr.innerHTML = `<td class="p-4 whitespace-nowrap text-slate-300">${new Date(a.timestamp).toLocaleTimeString()}<span class="text-xs text-slate-500 block">${new Date(a.timestamp).toLocaleDateString()}</span></td><td class="p-4 ${sevClass}">${sevLabel} (${a.severity})</td><td class="p-4 font-medium text-white group-hover:text-blue-300 transition">${a.attack_type}</td><td class="p-4 font-mono text-slate-400 text-xs">${a.source_ip || 'N/A'}</td><td class="p-4 text-right"><i class="fa-solid fa-chevron-right text-slate-600 group-hover:text-white transition"></i></td>`;
                tbody.appendChild(tr);
            });
        }
        function loadDetail(data) {
            currentAlertId = data.id; document.getElementById('detailId').innerText = `ID: ${data.shuffle_id || data.id}`;
            const aiHtml = data.ai_analysis ? marked.parse(data.ai_analysis) : '<div class="flex items-center gap-2 text-slate-500 animate-pulse"><i class="fa-solid fa-spinner fa-spin"></i> Analyzing...</div>';
            document.getElementById('detailContent').innerHTML = `<div class="space-y-4 animate-fadeIn"><div class="bg-gradient-to-r from-slate-800 to-slate-800/50 p-4 rounded-lg border border-slate-700 shadow-md"><h4 class="text-white font-bold text-lg mb-1 leading-tight">${data.title}</h4><p class="text-slate-400 text-xs mt-2 font-mono">${data.description}</p></div><div class="grid grid-cols-2 gap-3"><div class="bg-slate-800/50 p-3 rounded border border-slate-700"><div class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Rule ID</div><div class="text-blue-300 font-mono font-bold">${data.rule_id}</div></div><div class="bg-slate-800/50 p-3 rounded border border-slate-700"><div class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Source IP</div><div class="text-red-400 font-mono font-bold flex items-center gap-2">${data.source_ip}</div></div></div><div class="bg-slate-800 p-4 rounded-lg border border-blue-900/30 shadow-inner relative overflow-hidden group"><div class="absolute top-0 right-0 p-2 opacity-5 group-hover:opacity-10 transition"><i class="fa-solid fa-brain text-6xl text-blue-500"></i></div><div class="flex items-center gap-2 mb-3 border-b border-slate-700/50 pb-2 relative z-10"><i class="fa-solid fa-wand-magic-sparkles text-purple-400"></i><h4 class="font-bold text-purple-300 text-sm uppercase tracking-wide">AI Analysis Report</h4></div><div class="prose prose-invert prose-sm text-slate-300 relative z-10 leading-relaxed max-w-none text-xs">${aiHtml}</div></div><div class="mt-2"><div class="text-[10px] text-slate-500 uppercase font-bold mb-1">Raw Log</div><pre class="bg-black/40 p-3 rounded text-[10px] text-green-500/90 font-mono overflow-x-auto border border-slate-800/50 max-h-40 scrollbar-thin">${JSON.stringify(data.full_log, null, 2)}</pre></div></div>`;
        }
        async function sendChat() {
            const input = document.getElementById('chatInput'); const q = input.value.trim(); if(!q) return;
            const history = document.getElementById('chatHistory'); history.innerHTML += `<div class="chat-msg chat-user animate-slideUp">${q}</div>`; input.value = ''; history.scrollTop = history.scrollHeight;
            const loadingId = 'loading-' + Date.now(); history.innerHTML += `<div id="${loadingId}" class="chat-msg chat-bot flex items-center gap-2 text-slate-400"><i class="fa-solid fa-circle-notch fa-spin"></i> AI thinking...</div>`; history.scrollTop = history.scrollHeight;
            let reply = "";
            if(isDemoMode) { await new Promise(r => setTimeout(r, 800)); reply = `**(Demo Mode)**: Backend disconnected.`; } 
            else { try { const res = await fetch(`${API_URL}/chatbot/`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({question: q, context_alert_id: currentAlertId}) }); const data = await res.json(); reply = data.response; } catch(e) { reply = "⚠️ Error connecting to AI."; } }
            document.getElementById(loadingId).remove(); history.innerHTML += `<div class="chat-msg chat-bot animate-fadeIn">${marked.parse(reply)}</div>`; history.scrollTop = history.scrollHeight;
        }
        document.getElementById('chatForm').addEventListener('submit', function(e) { e.preventDefault(); sendChat(); });
        function clearChat() { document.getElementById('chatHistory').innerHTML = '<div class="chat-msg chat-bot shadow-sm">Chat cleared.</div>'; }
        fetchAlerts(); setInterval(() => { if(!isDemoMode) fetchAlerts(); }, 10000);
    </script>
</body>
</html>
""",

    # ---------------------------------------------------------
    # 7. REQUIREMENTS & README
    # ---------------------------------------------------------
    "requirements.txt": """
fastapi
uvicorn
sqlalchemy
pydantic
requests
pymysql
cryptography
pydantic-settings
""",

    "README.md": """
# Security Alert Manager (SOC Dashboard)

## Cách chạy dự án:

1.  **Cài đặt thư viện:**
    `pip install -r requirements.txt`

2.  **Cài đặt AI (Ollama):**
    - Tải Ollama từ ollama.com
    - Chạy lệnh: `ollama run qwen2.5:1.5b`

3.  **Chạy Server Backend:**
    `python -m app.main`
    *(Lưu ý: Chạy lệnh này tại thư mục chứa file install_project.py)*

4.  **Mở Giao Diện:**
    - Vào thư mục `frontend` và click đúp `index.html`.
"""
}

def create_project():
    print(f"🚀 Đang khởi tạo dự án tại: {BASE_DIR}")
    
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)
        
    for filepath, content in project_files.items():
        full_path = os.path.join(BASE_DIR, filepath)
        
        # Tạo thư mục con nếu chưa có
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        
        # Ghi nội dung vào file
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content.strip())
            
        print(f"   ✅ Đã tạo: {filepath}")

    print("\n🎉 HOÀN TẤT! Đã tải xong source code.")
    print(f"👉 Hãy mở thư mục '{BASE_DIR}' và làm theo hướng dẫn trong README.md")

if __name__ == "__main__":
    create_project()