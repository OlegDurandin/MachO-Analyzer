#!/usr/bin/env python3

import os
import argparse
from typing import Dict, Any, List, Tuple
from macholib.MachO import MachO
from core.plugin_manager import PluginManager
from core.plugin_base import MachOPlugin
from core.security_analyzer import SecurityIssue, SeverityLevel
from core.symbol_analyzer import Symbol, SymbolType, LibraryInfo
from core.embedded_data_analyzer import EmbeddedData
from core.sign_analyzer import SignInfo, SignType, SignStatus
from core.permission_analyzer import PermissionAnalyzer
from core.debug_analyzer import DebugInfo
from core.constants import (
    CPU_TYPE_X86,
    CPU_TYPE_X86_64,
    CPU_TYPE_ARM,
    CPU_TYPE_ARM64,
    CPU_TYPE_ARM64_32,
    CPU_TYPE_POWERPC,
    CPU_TYPE_POWERPC64
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.style import Style

console = Console()

class MachOAnalyzer:
    """Основной класс для анализа Mach-O файлов"""
    
    def __init__(self, file_path: str):
        """Инициализация анализатора"""
        self.file_path = file_path
        self.macho = MachO(file_path)
        self.plugin_manager = PluginManager()
        self.plugin_manager.load_plugins(os.path.join(os.path.dirname(__file__), "plugins"))
        
        # Упорядоченный список плагинов для анализа
        self.ordered_plugins = [
            "header_analyzer",      # 1. Основная информация
            "security_analyzer",    # 2. Безопасность
            "vulnerability_analyzer", # 3. Уязвимости
            "symbol_analyzer",      # 4. Символы и импорты
            "network_analyzer",     # 5. Сетевая активность
            "embedded_data_analyzer", # 6. Встроенные данные
            "sign_analyzer",        # 7. Подписи
            "permission_analyzer",  # 8. Разрешения
            "debug_analyzer",       # 9. Отладочная информация
            "obfuscation_analyzer", # 10. Обфускация
            "persistence_analyzer", # 11. Персистентность
            "malware_patterns"      # 12. Анализ паттернов вредоносного кода
        ]

    def print_table(self, title: str, columns: List[str], rows: List[List[str]], style: str = "bold") -> None:
        """Выводит таблицу с данными"""
        table = Table(title=title, show_header=True, header_style=style)
        for col in columns:
            table.add_column(col, style=style)
        for row in rows:
            table.add_row(*row)
        console.print(table)
        console.print()

    def print_info_panel(self, title: str, content: str) -> None:
        """Выводит информационную панель"""
        console.print(Panel(content, title=title, border_style="blue"))
        console.print()

    def print_error(self, message: str) -> None:
        """Выводит сообщение об ошибке"""
        console.print(f"[red]Ошибка: {message}[/red]")
        console.print()

    def print_warning(self, message: str) -> None:
        """Выводит предупреждение"""
        console.print(f"[yellow]Предупреждение: {message}[/yellow]")
        console.print()

    def print_success(self, message: str) -> None:
        """Выводит сообщение об успехе"""
        console.print(f"[green]Успех: {message}[/green]")
        console.print()

    def print_section(self, title: str, content: str = "") -> None:
        """Выводит секцию с заголовком"""
        console.print(f"\n[bold blue]{title}[/bold blue]")
        if content:
            console.print(content)
            console.print()

    def _get_arch_name(self, cputype: int, subcpu: int) -> str:
        """Возвращает название архитектуры на основе типа CPU"""
        arch_map = {
            CPU_TYPE_X86: "x86",
            CPU_TYPE_X86_64: "x86_64",
            CPU_TYPE_ARM: "arm",
            CPU_TYPE_ARM64: "arm64",
            CPU_TYPE_ARM64_32: "arm64_32",
            CPU_TYPE_POWERPC: "ppc",
            CPU_TYPE_POWERPC64: "ppc64"
        }
        return arch_map.get(cputype, "Unknown")
    
    def _process_plugin_results(self, plugin_name: str, plugin: MachOPlugin, results: Any, header: Any = None) -> None:
        """Обрабатывает результаты плагина"""
        try:
            # Проверяем тип результатов
            if isinstance(results, str):
                self.print_info_panel(plugin_name, results)
                return
                
            # Обрабатываем результаты в зависимости от типа плагина
            if plugin_name == "header_analyzer":
                header_info = results[f"header_{header.header.cputype}_{header.header.cpusubtype}"]
                plugin._print_header_info(header_info)
            elif plugin_name == "security_analyzer":
                plugin._print_security_info(results)
            elif plugin_name == "symbol_analyzer":
                symbols, libraries = results
                plugin._print_symbol_info(symbols, libraries)
            elif plugin_name == "embedded_data_analyzer":
                plugin._print_embedded_data(results)
            elif plugin_name == "sign_analyzer":
                plugin._print_sign_info(results)
            elif plugin_name == "permission_analyzer":
                plugin._print_permissions_info(results)
            elif plugin_name == "debug_analyzer":
                plugin._print_debug_info(results)
            elif plugin_name == "vulnerability_analyzer":
                plugin._print_vulnerability_info(results)
            elif plugin_name == "obfuscation_analyzer":
                plugin._print_obfuscation_info(results)
            elif plugin_name == "import_export_analyzer":
                plugin._print_import_export_info(results)
            elif plugin_name == "persistence_analyzer":
                plugin._print_persistence_info(results)
            elif plugin_name == "malware_patterns":
                plugin._print_patterns_info(results)
        except Exception as e:
            self.print_error(f"Ошибка при обработке результатов плагина {plugin_name}: {str(e)}")
            raise

    def _get_available_ordered_plugins(self) -> List[str]:
        """Возвращает список доступных плагинов в установленном порядке"""
        available_plugins = self.plugin_manager.get_available_plugins()
        return [plugin for plugin in self.ordered_plugins if plugin in available_plugins]

    def analyze(self) -> None:
        """Запускает анализ Mach-O файла"""
        try:
            # Проверяем, является ли файл FAT
            if len(self.macho.headers) > 1:
                self.print_info_panel("Тип файла", "FAT (Universal Binary)")
                self.print_section("Архитектуры", "")
                
                # Получаем имена архитектур
                arch_names = [self._get_arch_name(header.header.cputype, header.header.cpusubtype) for header in self.macho.headers]
                for arch in arch_names:
                    self.print_info_panel("Архитектура", arch)
                
                # Анализируем каждую архитектуру
                for i, header in enumerate(self.macho.headers):
                    self.print_section(f"Анализ архитектуры {arch_names[i]}", "")
                    
                    try:
                        # Создаем новый экземпляр MachO для текущей архитектуры
                        current_macho = MachO(self.file_path)
                        current_macho.headers = [header]
                        
                        # Запускаем плагины в установленном порядке
                        for plugin_name in self._get_available_ordered_plugins():
                            try:
                                plugin = self.plugin_manager.instantiate_plugin(plugin_name, current_macho, self.file_path)
                                results = plugin.analyze()
                                self._process_plugin_results(plugin_name, plugin, results, header)
                            except Exception as e:
                                self.print_error(f"Ошибка выполнения плагина {plugin_name}: {str(e)}")
                                continue
                    except Exception as e:
                        self.print_error(f"Ошибка при анализе архитектуры {arch_names[i]}: {str(e)}")
                        continue
            else:
                # Анализируем одиночный Mach-O файл
                header = self.macho.headers[0]
                self.print_info_panel("Тип файла", "Mach-O")
                self.print_section("Анализ", "")
                
                # Запускаем плагины в установленном порядке
                for plugin_name in self._get_available_ordered_plugins():
                    try:
                        plugin = self.plugin_manager.instantiate_plugin(plugin_name, self.macho, self.file_path)
                        results = plugin.analyze()
                        self._process_plugin_results(plugin_name, plugin, results, header)
                    except Exception as e:
                        self.print_error(f"Ошибка выполнения плагина {plugin_name}: {str(e)}")
                        continue
                        
        except Exception as e:
            self.print_error(f"Ошибка при анализе файла: {str(e)}")
    


def main():
    parser = argparse.ArgumentParser(description='MachO File Analyzer')
    parser.add_argument('file', help='Path to MachO file to analyze')
    parser.add_argument('--headers', action='store_true', help='Show file headers')
    parser.add_argument('--segments', action='store_true', help='Show segments and sections')
    parser.add_argument('--security', action='store_true', help='Show security analysis')
    parser.add_argument('--all', action='store_true', help='Show all information')
    
    args = parser.parse_args()

    try:
        analyzer = MachOAnalyzer(args.file)
        
        if args.all:
            analyzer.analyze()
        else:
            if args.headers or args.segments or args.security:
                # Проверяем, является ли файл FAT
                is_fat = len(analyzer.macho.headers) > 1
                if is_fat:
                    analyzer.print_info_panel("Тип файла", "FAT (Universal Binary)")
                    analyzer.print_section("Архитектуры", 
                        "\n".join([f"- {analyzer._get_arch_name(header.header.cputype, header.header.cpusubtype)}" 
                                  for header in analyzer.macho.headers]))
                
                # Анализируем каждую архитектуру
                for header in analyzer.macho.headers:
                    try:
                        if is_fat:
                            analyzer.print_section(f"Анализ архитектуры {analyzer._get_arch_name(header.header.cputype, header.header.cpusubtype)}", "")
                        
                        # Запускаем только запрошенные плагины в установленном порядке
                        for plugin_name in analyzer._get_available_ordered_plugins():
                            if (args.headers and plugin_name == "header_analyzer") or \
                               (args.security and plugin_name == "security_analyzer") or \
                               (args.segments and plugin_name == "header_analyzer"):
                                try:
                                    plugin = analyzer.plugin_manager.instantiate_plugin(plugin_name, analyzer.macho, analyzer.file_path)
                                    results = plugin.analyze()
                                    analyzer._process_plugin_results(plugin_name, plugin, results, header)
                                except Exception as e:
                                    analyzer.print_error(f"Ошибка выполнения плагина {plugin_name}: {str(e)}")
                                    continue
                    except Exception as e:
                        analyzer.print_error(f"Ошибка при анализе архитектуры {header.header.cputype}_{header.header.cpusubtype}: {str(e)}")
                        continue
            else:
                analyzer.analyze()
    except Exception as e:
        analyzer.print_error(f"Ошибка при анализе файла: {str(e)}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main()) 