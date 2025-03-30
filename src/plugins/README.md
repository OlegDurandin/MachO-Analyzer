# Разработка плагинов для Mach-O Analyzer

Этот документ описывает, как создавать плагины для Mach-O Analyzer.

## Структура плагина

Каждый плагин должен быть отдельным Python-модулем в директории `plugins/`. Плагин должен содержать класс, наследующийся от `MachOPlugin`.

Пример структуры плагина:

```python
from core.plugin_base import MachOPlugin
from typing import Dict, Any

class MyAnalyzerPlugin(MachOPlugin):
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        # Инициализация вашего анализатора
    
    def analyze(self) -> Dict[str, Any]:
        # Реализация анализа
        return {
            "result": "данные анализа"
        }
    
    def get_name(self) -> str:
        return "my_analyzer"
    
    def get_description(self) -> str:
        return "Описание функционала плагина"
    
    def get_version(self) -> str:
        return "1.0.0"
```

## Обязательные методы

Каждый плагин должен реализовать следующие методы:

1. `analyze()` - основной метод анализа, возвращающий словарь с результатами
2. `get_name()` - возвращает уникальное имя плагина
3. `get_description()` - возвращает описание функционала плагина
4. `get_version()` - возвращает версию плагина

## Опциональные методы

1. `get_dependencies()` - возвращает список зависимостей плагина
2. `is_compatible()` - проверяет совместимость плагина с текущим файлом

## Примеры плагинов

- `header_analyzer_plugin.py` - анализ заголовков Mach-O файла
- `security_analyzer_plugin.py` - анализ механизмов безопасности
- `symbol_analyzer_plugin.py` - анализ символов и импортов

## Лучшие практики

1. Каждый плагин должен быть независимым и не зависеть от других плагинов
2. Результаты анализа должны быть в формате словаря с понятными ключами
3. Обрабатывайте возможные ошибки и возвращайте информативные сообщения
4. Документируйте код и добавляйте типы данных
5. Добавляйте тесты для вашего плагина

## Установка плагинов

Плагины автоматически загружаются из директории `plugins/` при запуске анализатора. Для добавления нового плагина:

1. Создайте новый файл в директории `plugins/`
2. Реализуйте класс плагина
3. Перезапустите анализатор

## Отладка плагинов

Для отладки плагинов можно использовать:

```python
from macho_analyzer import MachOAnalyzer

analyzer = MachOAnalyzer("path/to/binary")
plugin_info = analyzer.get_plugin_info("my_analyzer")
results = analyzer.run_plugin("my_analyzer")
``` 