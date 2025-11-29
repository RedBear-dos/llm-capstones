from typing import Dict, Any
from datetime import datetime

class LogParser:
    @staticmethod
    def parse(data: Dict[str, Any]) -> Dict[str, Any]:
        # 1. Xử lý Timestamp
        ts_val = datetime.now()
        ts_str = data.get("timestamp")
        if ts_str:
            try:
                if '+' in ts_str: ts_str = ts_str.split('+')[0]
                ts_val = datetime.fromisoformat(ts_str)
            except: pass

        # ==========================================
        # CASE 1: LOG TỪ AI IDS (CUSTOM LOG)
        # ==========================================
        if data.get("app_name") == "ai_ids":
            # Log này dạng phẳng, lấy trực tiếp
            parsed = {
                "shuffle_id": str(data.get("suri_flow_id", datetime.now().timestamp())),
                "rule_id": "AI-IDS", # Đặt tên Rule riêng
                "timestamp": ts_val,
                "title": f"AI Detection: {str(data.get('alert_type')).title()}", # Ví dụ: AI Detection: Beaconing
                "description": f"AI Score: {data.get('ai_score')} | Label: {data.get('ai_label')}",
                
                # Yêu cầu: Set cứng Severity = 7
                "severity": 7,
                
                "full_log": data,
                "source_ip": data.get("src_ip", "N/A"),
                "destination_ip": data.get("dest_ip", "N/A"),
                "attack_type": str(data.get("alert_type", "AI Anomaly")).title(), # Beaconing
                "mitre_tactic": "Command and Control" # Giả định cho Beaconing
            }
            return parsed

        # ==========================================
        # CASE 2: LOG TỪ WAZUH / SURICATA (STANDARD)
        # ==========================================
        
        # 2. Bóc tách dữ liệu Wazuh
        all_fields = data.get("all_fields", {})
        rule_info = all_fields.get("rule", {})
        log_data = all_fields.get("data", {}) 
        agent_info = all_fields.get("agent", {})

        # --- Logic Severity ---
        severity_val = rule_info.get("level")
        if severity_val is None:
            severity_val = data.get("severity", 1)

        # --- Logic Destination IP ---
        agent_ip = agent_info.get("ip")
        dest_ip = agent_ip if agent_ip else (log_data.get("dest_ip") or log_data.get("destip"))
        if not dest_ip: dest_ip = "Local Server"

        # --- Logic Source IP ---
        src_ip = log_data.get("srcip") or log_data.get("src_ip") or "N/A"

        parsed = {
            "shuffle_id": str(data.get("id", datetime.now().timestamp())),
            "rule_id": str(data.get("rule_id", "000")),
            "timestamp": ts_val,
            "title": data.get("title", "Unknown Alert"),
            "description": data.get("text", str(data)),
            "severity": int(severity_val),
            "full_log": data,
            "source_ip": src_ip,       
            "destination_ip": dest_ip, 
            "attack_type": "Security Alert",
            "mitre_tactic": "Unknown"
        }

        # 3. MITRE Wazuh
        mitre = rule_info.get("mitre", {})
        if mitre:
            parsed["mitre_tactic"] = f"{mitre.get('id', [])} - {mitre.get('tactic', [])}"

        # 4. Phân loại Attack Type Wazuh
        rule_id = parsed["rule_id"]
        title_lower = parsed["title"].lower()

        if rule_id == "5551" or "failed login" in title_lower:
            parsed["attack_type"] = "SSH Brute-Force"
            parsed["source_ip"] = log_data.get("srcip", parsed["source_ip"])
        elif rule_id == "31103" or "sql injection" in title_lower:
            parsed["attack_type"] = "Web Attack (SQLi/XSS)"
        elif rule_id == "100501" or "file modification" in title_lower:
            parsed["attack_type"] = "Suspicious File Creation"
        elif rule_id == "100210" or "audit" in title_lower:
            parsed["attack_type"] = "Privilege Escalation"
            audit = log_data.get("audit", {})
            parsed["source_ip"] = f"User: {audit.get('uid', 'local')}"
        elif rule_id == "86601" or "nmap" in title_lower:
            parsed["attack_type"] = "Reconnaissance (Scan)"

        return parsed