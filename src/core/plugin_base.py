from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from macholib.MachO import MachO
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
import xml.etree.ElementTree as ET
from enum import Enum

console = Console()

class OutputFormat(Enum):
    """Форматы вывода результатов анализа"""
    CONSOLE = "console"
    JSON = "json"
    XML = "xml"

class MachOPlugin(ABC):
    """Базовый класс для всех плагинов анализатора Mach-O"""
    
    def __init__(self, macho: MachO, file_path: str):
        self.macho = macho
        self.file_path = file_path
    
    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """Основной метод анализа. Должен возвращать словарь с результатами"""
        pass
    
    @staticmethod
    @abstractmethod
    def get_name() -> str:
        """Возвращает имя плагина"""
        pass
    
    @staticmethod
    @abstractmethod
    def get_description() -> str:
        """Возвращает описание функционала плагина"""
        pass
    
    @staticmethod
    @abstractmethod
    def get_version() -> str:
        """Возвращает версию плагина"""
        pass
    
    def get_dependencies(self) -> List[str]:
        """Возвращает список зависимостей плагина"""
        return []
    
    def is_compatible(self) -> bool:
        """Проверяет совместимость плагина с текущим файлом"""
        return True 

    def print_table(self, title: str, columns: List[str], rows: List[List[str]], style: str = "bold magenta") -> None:
        """Выводит таблицу с данными"""
        table = Table(show_header=True, header_style=style, title=title)
        for column in columns:
            table.add_column(column)
        for row in rows:
            table.add_row(*row)
        console.print(table)
        console.print()

    def print_info_panel(self, title: str, content: str) -> None:
        """Выводит информационную панель"""
        console.print(Panel(content, title=title))
        console.print()

    def print_error(self, message: str) -> None:
        """Выводит сообщение об ошибке"""
        console.print(f"[red]Ошибка: {message}[/red]")

    def print_warning(self, message: str) -> None:
        """Выводит предупреждение"""
        console.print(f"[yellow]Предупреждение: {message}[/yellow]")

    def print_success(self, message: str) -> None:
        """Выводит сообщение об успехе"""
        console.print(f"[green]Успех: {message}[/green]")

    def print_section(self, title: str, content: str) -> None:
        """Выводит секцию с заголовком"""
        console.print(f"\n[bold blue]{title}[/bold blue]")
        console.print(content)
        console.print()

    def print_results(self, format: OutputFormat = OutputFormat.CONSOLE) -> None:
        """Выводит результаты анализа в указанном формате"""
        if self.results is None:
            self.results = self.analyze()
            
        if format == OutputFormat.CONSOLE:
            self._print_console()
        elif format == OutputFormat.JSON:
            self._print_json()
        elif format == OutputFormat.XML:
            self._print_xml()
    
    def export_results(self, format: OutputFormat) -> str:
        """Экспортирует результаты в указанном формате"""
        if self.results is None:
            self.results = self.analyze()
            
        if format == OutputFormat.JSON:
            return json.dumps(self.results, indent=2)
        elif format == OutputFormat.XML:
            return self._to_xml()
        else:
            raise ValueError(f"Неподдерживаемый формат экспорта: {format}")
    
    def _print_console(self) -> None:
        """Выводит результаты в консоль с форматированием"""
        try:
            if not self.results:
                console.print(Panel("Результаты анализа не найдены", title=self.get_name()))
                return
                
            # Выводим заголовок
            console.print(f"\n[bold magenta]{self.get_name()}[/bold magenta]")
            console.print(f"[italic]{self.get_description()}[/italic]\n")
            
            # Выводим основную информацию
            self._print_main_info()
            
            # Выводим детали
            self._print_details()
            
            # Выводим рекомендации, если есть
            if "recommendations" in self.results:
                self._print_recommendations()
                
        except Exception as e:
            console.print(f"[red]Ошибка при выводе результатов: {str(e)}[/red]")
    
    def _print_main_info(self) -> None:
        """Выводит основную информацию в виде таблицы"""
        if "main_info" in self.results:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Параметр", style="cyan")
            table.add_column("Значение", style="yellow")
            
            for key, value in self.results["main_info"].items():
                table.add_row(
                    key.replace("_", " ").title(),
                    str(value)
                )
            console.print(table)
    
    def _print_details(self) -> None:
        """Выводит детальную информацию"""
        if "details" in self.results:
            for section, items in self.results["details"].items():
                if items:
                    console.print(f"\n[bold {self._get_section_color(section)}]{section}[/bold {self._get_section_color(section)}]")
                    table = Table(show_header=True, header_style=f"bold {self._get_section_color(section)}")
                    
                    # Определяем колонки на основе данных
                    if isinstance(items, list) and items:
                        for key in items[0].keys():
                            table.add_column(key.replace("_", " ").title(), style="yellow")
                    
                    # Добавляем строки
                    for item in items:
                        table.add_row(*[str(v) for v in item.values()])
                    
                    console.print(table)
    
    def _print_recommendations(self) -> None:
        """Выводит рекомендации"""
        if self.results.get("recommendations"):
            console.print("\n[bold red]Рекомендации[/bold red]")
            for i, rec in enumerate(self.results["recommendations"], 1):
                console.print(f"{i}. {rec}")
    
    def _get_section_color(self, section: str) -> str:
        """Возвращает цвет для секции"""
        colors = {
            "security": "red",
            "vulnerabilities": "red",
            "permissions": "yellow",
            "network": "blue",
            "embedded": "green",
            "imports": "cyan",
            "exports": "cyan",
            "headers": "magenta",
            "segments": "blue",
            "sections": "green"
        }
        return colors.get(section.lower(), "white")
    
    def _print_json(self) -> None:
        """Выводит результаты в формате JSON"""
        print(json.dumps(self.results, indent=2))
    
    def _print_xml(self) -> None:
        """Выводит результаты в формате XML"""
        print(self._to_xml())
    
    def _to_xml(self) -> str:
        """Преобразует результаты в XML"""
        root = ET.Element("analysis")
        root.set("plugin", self.get_name())
        
        def dict_to_xml(parent, data):
            for key, value in data.items():
                if isinstance(value, dict):
                    child = ET.SubElement(parent, key)
                    dict_to_xml(child, value)
                elif isinstance(value, list):
                    child = ET.SubElement(parent, key)
                    for item in value:
                        if isinstance(item, dict):
                            item_elem = ET.SubElement(child, "item")
                            dict_to_xml(item_elem, item)
                        else:
                            ET.SubElement(child, "item").text = str(item)
                else:
                    ET.SubElement(parent, key).text = str(value)
        
        dict_to_xml(root, self.results)
        return ET.tostring(root, encoding='unicode', method='xml') 