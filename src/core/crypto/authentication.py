import re
import time
import logging
from typing import Tuple, Optional, Dict, Any

logger = logging.getLogger("Authentication")

COMMON_PASSWORDS = {"password", "123456", "qwerty", "password123", "admin", "123456789"}
LOCKOUT_WINDOW_SECONDS = 900  # 15 минут для сброса счетчика
DEFAULT_AUTO_LOCK_TIMEOUT = 3600  # 1 час (CACHE-2)


class SessionManager:
    """
    Управление сессией пользователя (AUTH-4).
    Хранит: login timestamp, last activity time, failed attempt count.
    """

    def __init__(self):
        self.login_timestamp: Optional[float] = None
        self.last_activity: Optional[float] = None
        self.failed_attempts: int = 0
        self.last_failed_time: float = 0
        self.auto_lock_timeout: int = DEFAULT_AUTO_LOCK_TIMEOUT
        self.auto_lock_on_minimize: bool = True

    def start_session(self):
        """Начало новой сессии при успешном входе."""
        current_time = time.time()
        self.login_timestamp = current_time
        self.last_activity = current_time
        logger.debug(f"Session started at {self.login_timestamp}")

    def update_activity(self):
        """Обновление времени последней активности."""
        if self.login_timestamp is not None:
            self.last_activity = time.time()
            logger.debug(f"Activity updated at {self.last_activity}")

    def end_session(self):
        """Завершение сессии (при выходе или блокировке)."""
        self.login_timestamp = None
        self.last_activity = None
        logger.debug("Session ended")

    def is_session_active(self) -> bool:
        """Проверка, активна ли сессия."""
        return self.login_timestamp is not None

    def get_session_duration(self) -> float:
        """Получение длительности сессии в секундах."""
        if self.login_timestamp is None:
            return 0
        return time.time() - self.login_timestamp

    def get_idle_time(self) -> float:
        """Получение времени простоя в секундах."""
        if self.last_activity is None:
            return 0
        return time.time() - self.last_activity

    def is_idle_expired(self) -> bool:
        """Проверка превышения таймаута неактивности (CACHE-2)."""
        if self.last_activity is None:
            return False
        return self.get_idle_time() >= self.auto_lock_timeout

    def get_remaining_idle_time(self) -> int:
        """Оставшееся время до авто-блокировки."""
        if self.last_activity is None:
            return 0
        remaining = self.auto_lock_timeout - self.get_idle_time()
        return max(0, int(remaining))

    def register_failed_attempt(self):
        """Регистрация неудачной попытки входа."""
        self.failed_attempts += 1
        self.last_failed_time = time.time()
        logger.info(f"Failed attempt #{self.failed_attempts}")

    def reset_failed_attempts(self):
        """Сброс счетчика неудачных попыток."""
        self.failed_attempts = 0
        self.last_failed_time = 0

    def get_session_info(self) -> Dict[str, Any]:
        """Получение информации о сессии."""
        return {
            "login_timestamp": self.login_timestamp,
            "last_activity": self.last_activity,
            "failed_attempts": self.failed_attempts,
            "session_duration": self.get_session_duration(),
            "idle_time": self.get_idle_time(),
            "is_locked_out": self._is_locked_out_internal(),
        }

    def _is_locked_out_internal(self) -> bool:
        """Внутренняя проверка блокировки (для get_session_info)."""
        if self.failed_attempts > 0 and (time.time() - self.last_failed_time > LOCKOUT_WINDOW_SECONDS):
            return False
        if self.failed_attempts >= 5:
            return time.time() - self.last_failed_time < 30.0
        elif self.failed_attempts >= 3:
            return time.time() - self.last_failed_time < 5.0
        elif self.failed_attempts >= 1:
            return time.time() - self.last_failed_time < 1.0
        return False


class AuthenticationService:
    """Описывает публичный класс AuthenticationService."""
    def __init__(self):
        self.session = SessionManager()

    @property
    def failed_attempts(self) -> int:
        """Описывает публичное действие failed attempts."""
        return self.session.failed_attempts

    @property
    def last_failed_time(self) -> float:
        """Описывает публичное действие last failed time."""
        return self.session.last_failed_time

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Проверяет password strength."""
        if len(password) < 12:
            return False, "Минимальная длина пароля: 12 символов."
        
        if password.lower() in COMMON_PASSWORDS:
            return False, "Пароль слишком распространен."

        checks = [
            (r'[A-Z]', "заглавными буквами"),
            (r'[a-z]', "строчными буквами"),
            (r'[0-9]', "цифрами"),
            (r'[^A-Za-z0-9]', "специальными символами")
        ]
        
        missing = []
        for pattern, name in checks:
            if not re.search(pattern, password):
                missing.append(name)
        
        if missing:
            return False, f"Пароль должен содержать: {', '.join(missing)}."
            
        return True, "Пароль надежный."

    def get_backoff_delay(self) -> float:
        """Возвращает данные для backoff delay."""
        if self.session.failed_attempts >= 5:
            return 30.0
        elif self.session.failed_attempts >= 3:
            return 5.0
        elif self.session.failed_attempts >= 1:
            return 1.0
        return 0.0

    def register_failed_attempt(self):
        """Описывает публичное действие register failed attempt."""
        self.session.register_failed_attempt()

    def reset_attempts(self):
        """Описывает публичное действие reset attempts."""
        self.session.reset_failed_attempts()

    def start_session(self):
        """Начало сессии при успешном входе (AUTH-4)."""
        self.session.start_session()

    def update_activity(self):
        """Обновление активности (AUTH-4, CACHE-2)."""
        self.session.update_activity()

    def end_session(self):
        """Завершение сессии (AUTH-4)."""
        self.session.end_session()

    def is_session_active(self) -> bool:
        """Проверка активности сессии."""
        return self.session.is_session_active()

    def is_idle_expired(self) -> bool:
        """Проверка истечения таймаута неактивности (CACHE-2)."""
        return self.session.is_idle_expired()

    def get_session_info(self) -> Dict[str, Any]:
        """Получение информации о сессии (AUTH-4)."""
        return self.session.get_session_info()

    def set_auto_lock_timeout(self, seconds: int):
        """Установка таймаута авто-блокировки (CACHE-2)."""
        self.session.auto_lock_timeout = max(60, seconds) 

    def set_auto_lock_on_minimize(self, enabled: bool):
        """Включение/отключение авто-блокировки при сворачивании (CACHE-2)."""
        self.session.auto_lock_on_minimize = enabled

    def is_locked_out(self) -> bool:
        # Сброс счетчика после долгого перерыва
        """Описывает публичное действие is locked out."""
        if self.session.failed_attempts > 0 and (time.time() - self.session.last_failed_time > LOCKOUT_WINDOW_SECONDS):
            self.session.reset_failed_attempts()
            return False

        delay = self.get_backoff_delay()
        if delay > 0 and (time.time() - self.session.last_failed_time < delay):
            return True
        return False

    def get_remaining_lockout_time(self) -> int:
        """Возвращает данные для remaining lockout time."""
        delay = self.get_backoff_delay()
        elapsed = time.time() - self.session.last_failed_time
        return max(0, int(delay - elapsed))