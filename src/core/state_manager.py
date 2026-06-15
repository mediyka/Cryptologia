import time

class StateManager:
    #Централизованное управление состоянием приложения.
    #Требование: CFG-1
    """Описывает публичный класс StateManager."""
    def __init__(self):
        self.is_locked = True
        self.current_user = None
        
        # Параметры таймеров
        self.last_activity_time = time.time()
        self.clipboard_clear_time = None
        
    def login(self, username: str):
        """Описывает публичное действие login."""
        self.is_locked = False
        self.current_user = username
        self.update_activity()

    def logout(self):
        """Описывает публичное действие logout."""
        self.is_locked = True
        self.current_user = None

    def update_activity(self):
#Сброс таймера неактивности.
        """Обновляет activity."""
        self.last_activity_time = time.time()

    def check_inactivity(self, timeout_minutes: int) -> bool:
#Проверка, нужно ли блокировать сессию.
        """Описывает публичное действие check inactivity."""
        if self.is_locked:
            return False
            
        elapsed = time.time() - self.last_activity_time
        if elapsed > timeout_minutes * 60:
            return True
        return False

#глобальный экземпляр
state_manager = StateManager()