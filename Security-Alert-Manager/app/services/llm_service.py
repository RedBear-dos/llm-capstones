import requests
import logging
import json
from sqlalchemy import desc
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.alert import Alert

logger = logging.getLogger(__name__)

class LLMService:
    @staticmethod
    def mock_response(prompt_type: str) -> str:
        if prompt_type == "analysis":
            return "**⚠️ AI Offline:**\nKhông kết nối được Ollama. Phân tích giả lập:\n1. **Hành vi:** Bất thường.\n2. **Rủi ro:** Trung bình.\n3. **Khuyến nghị:** Kiểm tra log."
        return "Tôi đang ở chế độ Offline. Vui lòng bật Ollama để tôi có thể đọc dữ liệu thực tế."

    @staticmethod
    def analyze_alert(alert_id: int, db: Session):
        """
        Hàm này tạo ra báo cáo AI Analysis tự động khi có log mới.
        Nằm ở: app/services/llm_service.py
        """
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert: return

        # Tóm tắt log để gửi cho AI
        log_summary = json.dumps(alert.full_log, default=str)[:3000]

        # --- [KHUÔN MẪU PROMPT MỚI] ---
        prompt = f"""
        Bạn là chuyên gia SOC Analyst Level 3. Nhiệm vụ: Phân tích log JSON và viết báo cáo sự cố.
        
        [DỮ LIỆU LOG]:
        {log_summary}
        
        [QUY TẮC XÁC ĐỊNH ĐỐI TƯỢNG]:
        - **Attacker (Kẻ tấn công)**: Ưu tiên lấy `data.srcip` hoặc `src_ip`.
        - **Victim (Nạn nhân)**: Ưu tiên lấy `agent.ip` hoặc `data.dest_ip`.
        - **Tài khoản bị nhắm tới**: Tìm `data.user`, `data.username` (uid=0 là root).
        
        [YÊU CẦU ĐỊNH DẠNG TRẢ LỜI (BẮT BUỘC)]:
        Hãy trả lời bằng Tiếng Việt, tuân thủ tuyệt đối cấu trúc Markdown sau đây:

        ### 1. Tóm tắt sự cố
        - **Mô tả:** IP [Attacker] đang thực hiện hành vi [Tên hành vi] nhắm vào IP [Victim].
        - **Chi tiết:** [Mô tả ngắn gọn 1 câu về kỹ thuật tấn công].
        - **Tài khoản/File ảnh hưởng:** [Điền tên user hoặc file].

        ### 2. Đánh giá rủi ro
        - **Mức độ:** [Thấp/Trung bình/Cao/Nghiêm trọng]
        - **Lý do:** [Giải thích ngắn gọn tại sao lại đánh giá mức này].

        ### 3. Khuyến nghị xử lý
        - [Hành động 1: Ví dụ Block IP trên Firewall]
        - [Hành động 2: Ví dụ Reset mật khẩu/Cách ly máy]
        - [Hành động 3: Ví dụ Rà soát log hệ thống]
        """
        
        try:
            res = requests.post(settings.OLLAMA_URL, json={
                "model": settings.AI_MODEL, 
                "prompt": prompt, 
                "stream": False,
                "options": {"temperature": 0.1} # Nhiệt độ thấp để AI tuân thủ khuôn mẫu
            }, timeout=45)
            
            if res.status_code == 200:
                alert.ai_analysis = res.json().get("response", "")
            else:
                alert.ai_analysis = LLMService.mock_response("analysis")
        except:
            alert.ai_analysis = LLMService.mock_response("analysis")
        
        db.commit()

    @staticmethod
    def chat(question: str, context_alert_id: int = None, db: Session = None) -> str:
        """Chat thông minh"""
        
        specific_context = ""
        if context_alert_id and db:
            alert = db.query(Alert).filter(Alert.id == context_alert_id).first()
            if alert:
                full_log = json.dumps(alert.full_log, indent=2, default=str)
                specific_context = f"""
    [CHI TIẾT CẢNH BÁO ĐANG XEM (ID {alert.id})]:
    - Loại tấn công: {alert.attack_type}
    - Kẻ tấn công (Source IP): {alert.source_ip}
    - Nạn nhân (Dest/Agent IP): {alert.destination_ip}
    - Mức độ: {alert.severity}
    - Log Raw: ```json {full_log} ```
    """

        global_context = ""
        if db:
            recent_alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(5).all()
            summary_list = []
            for a in recent_alerts:
                summary_list.append(f"- ID: {a.id} | Time: {a.timestamp} | Sev: {a.severity} | Attack: {a.attack_type} | Src: {a.source_ip} -> Dst: {a.destination_ip}")
            
            global_context = f"""
    [TÌNH HÌNH HỆ THỐNG (5 CẢNH BÁO MỚI NHẤT)]:
    {chr(10).join(summary_list)}
    """

        final_prompt = f"""
    Bạn là trợ lý an ninh mạng (SOC Assistant). Dưới đây là dữ liệu hệ thống thực tế:
    
    {global_context}
    
    {specific_context}
    
    [ĐỊNH NGHĨA THUẬT NGỮ]:
    - **IP Tấn công (Attacker)**: Là Source IP.
    - **IP Bị ảnh hưởng (Victim)**: Là Destination IP (hoặc Agent IP).
    
    [YÊU CẦU QUAN TRỌNG]:
    - Trả lời câu hỏi dựa trên dữ liệu trên.
    - Nếu người dùng hỏi "IP bị ảnh hưởng" -> Hãy trả lời bằng IP Nạn nhân (Dest/Agent).
    - Nếu người dùng hỏi "IP tấn công" -> Hãy trả lời bằng IP Kẻ tấn công (Source).
    - Nếu thấy `uid=0` hoặc `uid=root` trong Log Raw, hãy trả lời user bị ảnh hưởng là "root".
    - Tuyệt đối KHÔNG bịa ra thông tin.
    
    [CÂU HỎI]: {question}
    [TRẢ LỜI]:
    """
        
        try:
            res = requests.post(settings.OLLAMA_URL, json={
                "model": settings.AI_MODEL, 
                "prompt": final_prompt, 
                "stream": False,
                "options": {"temperature": 0}
            }, timeout=20)
            
            if res.status_code == 200:
                return res.json().get("response")
        except Exception as e:
            logger.error(f"Chat Error: {e}")
            
        return LLMService.mock_response("chat")