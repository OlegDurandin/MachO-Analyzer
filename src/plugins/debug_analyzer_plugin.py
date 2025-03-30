from typing import Dict, Any
from core.plugin_base import MachOPlugin
from core.debug_analyzer import DebugAnalyzer, DebugInfo
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class DebugAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа отладочной информации Mach-O файла"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.debug_analyzer = DebugAnalyzer(self.macho, file_path)
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует отладочную информацию Mach-O файла"""
        debug_info = self.debug_analyzer.analyze()
        
        results = {
            "basic_info": {
                "has_dwarf": debug_info.has_dwarf,
                "has_dwarf_info": debug_info.has_dwarf_info,
                "has_debug_symbols": debug_info.has_debug_symbols,
                "has_stabs": debug_info.has_stabs,
                "dsym_uuid": debug_info.dsym_uuid
            },
            "debug_sections": [],
            "source_files": [],
            "includes": [],
            "functions": [],
            "protection_symbols": [],
            "debug_symbols": []
        }
        
        # DWARF секции
        if debug_info.debug_sections:
            for section in debug_info.debug_sections:
                results["debug_sections"].append({
                    "name": section,
                    "present": debug_info.dwarf_details.get(section.strip('_'), False)
                })
        
        # Исходные файлы
        if debug_info.source_files:
            results["source_files"] = debug_info.source_files
            
        # Include файлы
        if debug_info.includes:
            results["includes"] = debug_info.includes
            
        # Функции
        if debug_info.functions:
            results["functions"] = debug_info.functions
            
        # Символы защиты
        if debug_info.protection_symbols:
            results["protection_symbols"] = debug_info.protection_symbols
            
        # Отладочные символы
        if debug_info.debug_symbols:
            results["debug_symbols"] = debug_info.debug_symbols
            
        return results
    
    def _print_debug_info(self, debug_info: Dict[str, Any]) -> None:
        """Выводит информацию об отладочных данных"""
        try:
            # Основная информация
            basic_info = debug_info["basic_info"]
            console.print("\n[bold magenta]Основная информация об отладочной информации[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["DWARF", "Да" if basic_info["has_dwarf"] else "Нет"],
                ["DWARF Info", "Да" if basic_info["has_dwarf_info"] else "Нет"],
                ["Отладочные символы", "Да" if basic_info["has_debug_symbols"] else "Нет"],
                ["STABS", "Да" if basic_info["has_stabs"] else "Нет"]
            ]
            
            if basic_info["dsym_uuid"]:
                basic_rows.append(["dSYM UUID", basic_info["dsym_uuid"]])
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # DWARF секции
            if debug_info["debug_sections"]:
                console.print("\n[bold cyan]DWARF секции[/bold cyan]")
                sect_table = Table(show_header=True, header_style="bold cyan")
                sect_table.add_column("Секция", style="cyan")
                sect_table.add_column("Наличие", style="yellow")
                
                for section in debug_info["debug_sections"]:
                    sect_table.add_row(
                        section["name"],
                        "Да" if section["present"] else "Нет"
                    )
                console.print(sect_table)
            
            # Исходные файлы
            if debug_info["source_files"]:
                console.print("\n[bold yellow]Исходные файлы[/bold yellow]")
                for file in debug_info["source_files"]:
                    console.print(f"- {file}")
            
            # Include файлы
            if debug_info["includes"]:
                console.print("\n[bold cyan]Include файлы[/bold cyan]")
                for include in debug_info["includes"]:
                    console.print(f"- {include}")
            
            # Функции
            if debug_info["functions"]:
                console.print("\n[bold magenta]Функции[/bold magenta]")
                func_table = Table(show_header=True, header_style="bold magenta")
                func_table.add_column("Имя функции", style="cyan")
                
                for func in debug_info["functions"]:
                    func_table.add_row(func)
                console.print(func_table)
            
            # Символы защиты
            if debug_info["protection_symbols"]:
                console.print("\n[bold red]Символы защиты[/bold red]")
                prot_table = Table(show_header=True, header_style="bold red")
                prot_table.add_column("Символ", style="cyan")
                
                for sym in debug_info["protection_symbols"]:
                    prot_table.add_row(sym)
                console.print(prot_table)
            
            # Отладочные символы
            if debug_info["debug_symbols"]:
                console.print("\n[bold yellow]Отладочные символы[/bold yellow]")
                sym_table = Table(show_header=True, header_style="bold yellow")
                sym_table.add_column("Символ", style="cyan")
                
                for sym in debug_info["debug_symbols"]:
                    sym_table.add_row(sym)
                console.print(sym_table)
                
        except Exception as e:
            console.print(f"[red]Ошибка при выводе информации об отладке: {str(e)}[/red]")
    
    @staticmethod
    def get_name() -> str:
        return "debug_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует отладочную информацию Mach-O файла, включая DWARF и другие отладочные данные"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 