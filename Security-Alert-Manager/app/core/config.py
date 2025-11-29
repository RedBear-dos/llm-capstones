import os

class Settings:
    PROJECT_NAME: str = "Security Alert Manager"
    VERSION: str = "1.0.0"
    
    # --- DATABASE CONFIG ---
    # Đổi thành True nếu bạn muốn dùng MySQL (Production)
    USE_MYSQL: bool = False  
    
    MYSQL_USER: str = "root"
    MYSQL_PASSWORD: str = "MySQL@2025!"
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