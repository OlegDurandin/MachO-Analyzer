from typing import Dict, Any, List
from core.plugin_base import MachOPlugin
from core.embedded_data_analyzer import EmbeddedDataAnalyzer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class EmbeddedDataAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа встроенных данных в Mach-O файле"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.embedded_data_analyzer = EmbeddedDataAnalyzer(self.macho, file_path)
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует встроенные данные в Mach-O файле"""
        embedded_data = self.embedded_data_analyzer.analyze()
        
        # Группируем данные по секциям
        data_by_section = {}
        for item in embedded_data:
            if item.section not in data_by_section:
                data_by_section[item.section] = []
            data_by_section[item.section].append(item)
        
        results = {
            "basic_info": {
                "total_sections": len(data_by_section),
                "total_data_items": len(embedded_data),
                "total_size": sum(item.size for item in embedded_data)
            },
            "sections": []
        }
        
        # Анализируем каждую секцию
        for section_name, items in data_by_section.items():
            section_info = {
                "name": section_name,
                "offset": hex(items[0].offset) if items else "0x0",
                "size": sum(item.size for item in items),
                "data_items": []
            }
            
            # Анализируем каждое встроенное данное
            for item in items:
                # Обрабатываем content в зависимости от типа
                content = item.content
                if isinstance(content, bytes):
                    try:
                        content = content.decode('utf-8', errors='ignore')
                    except:
                        content = str(content[:50]) + "..." if len(content) > 50 else str(content)
                
                data_info = {
                    "type": item.data_type,
                    "offset": hex(item.offset),
                    "size": item.size,
                    "content": content[:100] + "..." if len(str(content)) > 100 else str(content),
                    "is_sensitive": item.is_sensitive,
                    "details": item.details
                }
                section_info["data_items"].append(data_info)
            
            results["sections"].append(section_info)
        
        return results
    
    def _print_embedded_data(self, embedded_data: Dict[str, Any]) -> None:
        """Выводит информацию о встроенных данных"""
        try:
            # Основная информация
            basic_info = embedded_data["basic_info"]
            console.print("\n[bold magenta]Основная информация о встроенных данных[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Всего секций", str(basic_info["total_sections"])],
                ["Всего элементов данных", str(basic_info["total_data_items"])],
                ["Общий размер", f"{basic_info['total_size']} байт"]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Информация по секциям
            for section in embedded_data["sections"]:
                console.print(f"\n[bold cyan]Секция: {section['name']}[/bold cyan]")
                console.print(f"Смещение: {section['offset']}")
                console.print(f"Размер: {section['size']} байт")
                
                if section["data_items"]:
                    data_table = Table(show_header=True, header_style="bold yellow")
                    data_table.add_column("Тип", style="cyan")
                    data_table.add_column("Смещение", style="yellow")
                    data_table.add_column("Размер", style="yellow")
                    data_table.add_column("Содержимое", style="green")
                    data_table.add_column("Чувствительные данные", style="red")
                    
                    for item in section["data_items"]:
                        data_table.add_row(
                            item["type"],
                            item["offset"],
                            str(item["size"]),
                            item["content"],
                            "Да" if item["is_sensitive"] else "Нет"
                        )
                    console.print(data_table)
                    
                    # Детали для чувствительных данных
                    for item in section["data_items"]:
                        if item["is_sensitive"] and item["details"]:
                            console.print(f"\n[bold red]Детали для {item['type']}:[/bold red]")
                            for key, value in item["details"].items():
                                console.print(f"- {key}: {value}")
                
        except Exception as e:
            console.print(f"[red]Ошибка при выводе информации о встроенных данных: {str(e)}[/red]")
    
    @staticmethod
    def get_name() -> str:
        return "embedded_data_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует встроенные данные в Mach-O файле, включая строки, изображения и скрипты"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 