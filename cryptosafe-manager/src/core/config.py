"""
Менеджер конфигурации приложения.
"""
import os
from pathlib import Path
from dotenv import load_dotenv


class Config:
    """Класс для управления конфигурацией (Singleton)."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        load_dotenv()
        
        self.APP_NAME = os.getenv('APP_NAME', 'CryptoSafe Manager')
        self.APP_VERSION = os.getenv('APP_VERSION', '1.0.0-sprint1')
        
        db_path = os.getenv('DB_PATH', '~/.cryptosafe/vault.db')
        self.DB_PATH = Path(db_path).expanduser().resolve()
        self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        self.CLIPBOARD_TIMEOUT = int(os.getenv('CLIPBOARD_TIMEOUT', '30'))
        self.MIN_PASSWORD_LENGTH = int(os.getenv('MIN_PASSWORD_LENGTH', '8'))
        
        self._initialized = True


config = Config()
