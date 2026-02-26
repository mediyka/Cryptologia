"""
Система событий (Event Bus).
"""
from typing import Dict, List, Callable, Any
from enum import Enum
from datetime import datetime


class EventType(Enum):
    """Типы событий в системе."""
    ENTRY_ADDED = "entry_added"
    ENTRY_UPDATED = "entry_updated"
    ENTRY_DELETED = "entry_deleted"
    USER_LOGGED_IN = "user_logged_in"
    USER_LOGGED_OUT = "user_logged_out"
    CLIPBOARD_COPIED = "clipboard_copied"
    CLIPBOARD_CLEARED = "clipboard_cleared"


class Event:
    """Класс события с метаданными."""
    
    def __init__(self, event_type: EventType, data: Any = None, source: str = None):
        self.type = event_type
        self.data = data
        self.source = source
        self.timestamp = datetime.now()


class EventBus:
    """Шина событий (Singleton)."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._subscribers = {}
        return cls._instance
    
    def subscribe(self, event_type: EventType, callback: Callable) -> None:
        """Подписывает callback на событие."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        
        if callback not in self._subscribers[event_type]:
            self._subscribers[event_type].append(callback)
    
    def emit(self, event_type: EventType, data: Any = None, source: str = None) -> None:
        """Публикует событие."""
        if event_type not in self._subscribers:
            return
        
        event = Event(event_type, data, source)
        for callback in self._subscribers[event_type]:
            try:
                callback(event)
            except Exception as e:
                print(f"Error in callback: {e}")


event_bus = EventBus()


class AuditLogger:
    """Заглушка для журнала аудита."""
    
    def __init__(self):
        self.event_bus = event_bus
        self.log_entries = []
        self._subscribe_to_events()
    
    def _subscribe_to_events(self):
        events_to_log = [
            EventType.ENTRY_ADDED, EventType.ENTRY_UPDATED,
            EventType.ENTRY_DELETED, EventType.USER_LOGGED_IN,
            EventType.USER_LOGGED_OUT, EventType.CLIPBOARD_COPIED
        ]
        
        for event_type in events_to_log:
            self.event_bus.subscribe(event_type, self._on_event)
    
    def _on_event(self, event: Event):
        log_entry = {
            'timestamp': event.timestamp,
            'type': event.type.value,
            'data': str(event.data)
        }
        self.log_entries.append(log_entry)
        print(f"[AUDIT] {event.timestamp.strftime('%H:%M:%S')}: {event.type.value}")
