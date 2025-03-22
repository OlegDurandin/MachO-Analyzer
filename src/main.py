#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
import argparse
import sys
from datetime import datetime
from core.header_analyzer import HeaderAnalyzer
from core.security_analyzer import SecurityAnalyzer, SeverityLevel, SecurityIssue
from core.sign_analyzer import SignAnalyzer
from core.symbol_analyzer import SymbolAnalyzer, SymbolType
from core.permission_analyzer import PermissionAnalyzer
from core.constants import FLAG_DESCRIPTIONS
from typing import Optional, List
import os
from macholib.MachO import MachO
from macholib.mach_o import *
from core.embedded_data_analyzer import EmbeddedDataAnalyzer, EmbeddedData
from core.debug_analyzer import DebugAnalyzer
#from tabulate import tabulate

console = Console()

class MachOAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.macho = MachO(file_path)
        self.header_analyzer = HeaderAnalyzer(self.macho)
        self.security_analyzer = SecurityAnalyzer(self.macho, file_path)
        self.sign_analyzer = SignAnalyzer(file_path)
        self.symbol_analyzer = SymbolAnalyzer(self.macho, file_path)
        self.embedded_data_analyzer = EmbeddedDataAnalyzer(self.macho, file_path)
        self.permission_analyzer = PermissionAnalyzer(self.macho, file_path)
        self.debug_analyzer = DebugAnalyzer(self.macho, file_path)

    def _print_file_info(self):
        """Вывести базовую информацию о файле"""
        file_info = self.header_analyzer.get_file_info()
        console.print(Panel(f"[bold blue]Файл:[/bold blue] {self.file_path}"))
        console.print(f"[bold green]Размер:[/bold green] {file_info['size'] / 1024:.2f} Кб ({file_info['size']} байт)")
        console.print(f"[bold green]Дата модификации:[/bold green] {file_info['modification_date']}\n")

    def _print_header_info(self, header):
        """Вывести информацию о заголовках"""
        # Основная информация
        basic_table = Table(show_header=True, header_style="bold magenta", title="Основная информация")
        basic_table.add_column("Параметр")
        basic_table.add_column("Значение")
        
        basic_table.add_row("Magic", self.header_analyzer._get_magic(header))
        basic_table.add_row("Битность", "64-bit" if header.header.magic in (MH_MAGIC_64, MH_CIGAM_64) else "32-bit")
        basic_table.add_row("CPU Type", self.header_analyzer._get_cpu_type(header.header.cputype))
        basic_table.add_row("CPU Subtype", str(header.header.cpusubtype))
        basic_table.add_row("Тип файла", self.header_analyzer._get_file_type(header.header.filetype))
        basic_table.add_row("Количество команд", str(header.header.ncmds))
        basic_table.add_row("Размер команд", f"{header.header.sizeofcmds} байт")
        if header.header.reserved != 0:
            basic_table.add_row("Reserved", str(header.header.reserved))
        console.print(basic_table)
        console.print()

        # Версии и идентификаторы
        load_cmd_data = self.header_analyzer._get_load_command_data(header)
        version_table = Table(show_header=True, header_style="bold cyan", title="Версии и идентификаторы")
        version_table.add_column("Параметр")
        version_table.add_column("Значение")
        
        if load_cmd_data['uuid']:
            version_table.add_row("UUID", load_cmd_data['uuid'])
        if load_cmd_data['min_version']:
            version_table.add_row("Минимальная версия OS", load_cmd_data['min_version'])
        if load_cmd_data['sdk_version']:
            version_table.add_row("Версия SDK", load_cmd_data['sdk_version'])
        if load_cmd_data['source_version']:
            version_table.add_row("Версия исходного кода", load_cmd_data['source_version'])
        if load_cmd_data['build_version']:
            version_table.add_row("Версия сборки", load_cmd_data['build_version'])
        
        if version_table.row_count > 0:
            console.print(version_table)
            console.print()

        # Флаги
        flags_table = Table(show_header=True, header_style="bold yellow", title="Флаги")
        flags_table.add_column("Флаг")
        flags_table.add_column("Описание")
        
        flags = self.header_analyzer._get_flags(header.header.flags)
        if flags:
            for flag in flags:
                flags_table.add_row(flag, FLAG_DESCRIPTIONS.get(flag, "Неизвестный флаг"))
        else:
            flags_table.add_row("None", "Флаги не установлены")
        
        console.print(flags_table)
        console.print()

    def _print_segments_info(self, segments):
        """Вывести информацию о сегментах"""
        if not segments:
            return

        console.print("\n[bold magenta]Сводка по сегментам:[/bold magenta]")
        summary_table = Table(show_header=True, header_style="bold cyan", title="Сводка по сегментам")
        summary_table.add_column("Имя")
        summary_table.add_column("VM адрес")
        summary_table.add_column("VM размер")
        summary_table.add_column("Смещение")
        summary_table.add_column("Размер")
        summary_table.add_column("Защита")
        summary_table.add_column("Секции")

        for segment in segments:
            summary_table.add_row(
                segment.name, 
                hex(segment.vm_address), 
                f"{segment.vm_size:,} байт", 
                str(segment.file_offset), 
                f"{segment.file_size:,} байт", 
                f"max={segment.max_prot}, init={segment.init_prot}", 
                str(len(segment.sections))
            )
        console.print(summary_table)

        console.print("\n[bold magenta]Секции:[/bold magenta]")
        for segment in segments:
            if segment.sections:
                sections_table = Table(show_header=True, header_style="bold green", title=f"Секции в {segment.name}")
                sections_table.add_column("Имя")
                sections_table.add_column("Адрес")
                sections_table.add_column("Размер")
                sections_table.add_column("Флаги")
                
                for section in segment.sections:
                    sections_table.add_row(
                        section.name,
                        hex(section.address),
                        f"{section.size:,}",
                        ", ".join(section.flags) if section.flags else "-"
                    )
                
                console.print(sections_table)
                console.print()

    def _print_security_info(self, issues):
        """Вывести информацию об анализе безопасности"""
        console.print("\n[bold]Анализ безопасности[/bold]")
        
        #     # Группируем по уровню серьезности
        by_severity = {
                SeverityLevel.CRITICAL: [],
                SeverityLevel.WARNING: [],
                SeverityLevel.INFO: []
            }
            
        for issue in issues:
                by_severity[issue.severity].append(issue)

        #     # Стили для разных уровней серьезности
        severity_styles = {
                SeverityLevel.CRITICAL: "bold red",
                SeverityLevel.WARNING: "bold yellow",
                SeverityLevel.INFO: "bold blue"
            }


        for severity, issues_list in by_severity.items():
            if not issues_list:
                continue

            security_table = Table(
                show_header=True,
                header_style=severity_styles[severity],
                title=f"{severity.value}"                
                )
                
            security_table.add_column("Описание", width=30)
            security_table.add_column("Детали", width=50)
            security_table.add_column("Рекомендации", width=40)

            for issue in issues_list:
                security_table.add_row(
                    issue.description,
                    Text(issue.details, overflow="fold"),
                    Text(issue.recommendation or "Нет рекомендаций", overflow="fold")
                )

            console.print(security_table)
            console.print()



        # Создаем сводную таблицу механизмов защиты
        # protection_table = Table(
        #     show_header=True,
        #     header_style="bold magenta",
        #     title="Механизмы защиты"
        # )
        
        # protection_table.add_column("Механизм")
        # protection_table.add_column("Статус")
        # protection_table.add_column("Описание")
        
        # Инициализируем механизмы защиты с более точными индикаторами
        # mechanisms = {
        #     "ASLR": {"enabled": any(("MH_PIE" in i.details or "рандомизация адресного пространства" in i.details.lower()) and not i.is_problem for i in issues), "description": ""},
        #     "Stack Canary": {"enabled": any(("stack_chk" in i.details.lower() or "__stack_chk_guard" in i.details.lower()) and not i.is_problem for i in issues), "description": ""},
        #     "DEP/NX": {"enabled": any(("стек не является исполняемым" in i.details.lower() or "nx" in i.details.lower()) and not i.is_problem for i in issues), "description": ""},
        #     "Code Signing": {"enabled": any("подпис" in i.details.lower() and not "самостоятельно" in i.details.lower() and not i.is_problem for i in issues), "description": ""},
        #     "RELRO": {"enabled": any("защита got" in i.details.lower() and not i.is_problem for i in issues), "description": ""},
        #     "FORTIFY_SOURCE": {"enabled": any("_chk" in i.details.lower() and not i.is_problem for i in issues), "description": ""},
        #     "Stack Protection": {"enabled": any("защита стека" in i.details.lower() and not i.is_problem for i in issues), "description": ""},
        #     "Sandbox": {"enabled": any("sandbox" in i.details.lower() and not i.is_problem for i in issues), "description": ""}
        # }
        
        # # Обновляем описания на основе найденных проблем
        # for issue in issues:
        #     desc_lower = issue.description.lower()
        #     if "aslr" in desc_lower:
        #         mechanisms["ASLR"]["description"] = issue.details
        #     elif "canary" in desc_lower or "stack_chk" in desc_lower:
        #         mechanisms["Stack Canary"]["description"] = issue.details
        #     elif "dep" in desc_lower or "nx" in desc_lower or "исполняемый стек" in desc_lower:
        #         mechanisms["DEP/NX"]["description"] = issue.details
        #     elif "подпись" in desc_lower:
        #         mechanisms["Code Signing"]["description"] = issue.details
        #     elif "relro" in desc_lower:
        #         mechanisms["RELRO"]["description"] = issue.details
        #     elif "fortify" in desc_lower:
        #         mechanisms["FORTIFY_SOURCE"]["description"] = issue.details
        #     elif "stack" in desc_lower and "protection" in desc_lower:
        #         mechanisms["Stack Protection"]["description"] = issue.details
        #     elif "sandbox" in desc_lower:
        #         mechanisms["Sandbox"]["description"] = issue.details
        
        # Подсчитываем включенные и отключенные механизмы
        # enabled = sum(1 for m in mechanisms.values() if m["enabled"])
        # total = len(mechanisms)
        
        # Определяем общий уровень защиты
        # if enabled == total:
        #     security_level = "[green]Высокий[/green]"
        # elif enabled >= total * 0.7:
        #     security_level = "[yellow]Средний[/yellow]"
        # else:
        #     security_level = "[red]Низкий[/red]"
            
        # console.print(f"\n[bold]Общий уровень защиты:[/bold] {security_level} ({enabled}/{total} механизмов включено)")
        
        # for mechanism, info in mechanisms.items():
        #     status = "[green]Включен[/green]" if info["enabled"] else "[red]Отключен[/red]"
        #     description = info["description"] if info["description"] else "-"
        #     protection_table.add_row(mechanism, status, description)
        
        # console.print(protection_table)
        # console.print()

        # if not issues:
        #     console.print("\n[bold green]Дополнительных проблем безопасности не обнаружено[/bold green]")
        #     return

        # Группируем проблемы по категориям
        # categories = {
        #     "Базовая защита": [],
        #     "Защита от переполнения": [],
        #     "Подпись кода": [],
        #     "Шифрование": [],
        #     "Библиотеки и символы": [],
        #     "Сетевая активность": [],
        #     "Отладка": [],
        #     "Уязвимости": []
        # }
        
        # for issue in issues:
        #     # Определяем категорию на основе описания
        #     if any(x in issue.description.lower() for x in ["aslr", "стек", "relro", "сегмент"]):
        #         categories["Базовая защита"].append(issue)
        #     elif any(x in issue.description.lower() for x in ["fortify", "canary", "переполнение"]):
        #         categories["Защита от переполнения"].append(issue)
        #     elif "подпись" in issue.description.lower():
        #         categories["Подпись кода"].append(issue)
        #     elif "шифрование" in issue.description.lower():
        #         categories["Шифрование"].append(issue)
        #     elif any(x in issue.description.lower() for x in ["библиотек", "символ", "импорт"]):
        #         categories["Библиотеки и символы"].append(issue)
        #     elif "сетев" in issue.description.lower():
        #         categories["Сетевая активность"].append(issue)
        #     elif any(x in issue.description.lower() for x in ["отладк", "debug"]):
        #         categories["Отладка"].append(issue)
        #     else:
        #         categories["Уязвимости"].append(issue)

        # # Создаем сводную таблицу проблем
        # summary_table = Table(
        #     show_header=True,
        #     header_style="bold magenta",
        #     title="Сводка проблем безопасности"
        # )
        
        # summary_table.add_column("Категория")
        # summary_table.add_column("Всего проблем")
        # summary_table.add_column("Критических")
        # summary_table.add_column("Предупреждений")
        # summary_table.add_column("Информационных")

        # total_critical = 0
        # total_warnings = 0
        # total_info = 0

        # for category, category_issues in categories.items():
        #     if not category_issues:
        #         continue
                
        #     critical = len([i for i in category_issues if i.severity == SeverityLevel.CRITICAL])
        #     warnings = len([i for i in category_issues if i.severity == SeverityLevel.WARNING])
        #     info = len([i for i in category_issues if i.severity == SeverityLevel.INFO])
            
        #     total_critical += critical
        #     total_warnings += warnings
        #     total_info += info
            
        #     summary_table.add_row(
        #         category,
        #         str(len(category_issues)),
        #         f"[red]{critical}[/red]" if critical else "0",
        #         f"[yellow]{warnings}[/yellow]" if warnings else "0",
        #         f"[blue]{info}[/blue]" if info else "0"
        #     )

        # summary_table.add_row(
        #     "[bold]Всего[/bold]",
        #     str(total_critical + total_warnings + total_info),
        #     f"[red]{total_critical}[/red]",
        #     f"[yellow]{total_warnings}[/yellow]",
        #     f"[blue]{total_info}[/blue]"
        # )

        # console.print(summary_table)
        # console.print()

        # Выводим детальную информацию по категориям
        # for category, category_issues in categories.items():
        #     if not category_issues:
        #         continue

        #     console.print(f"\n[bold]{category}[/bold]")
            
        #     # Группируем по уровню серьезности
        #     by_severity = {
        #         SeverityLevel.CRITICAL: [],
        #         SeverityLevel.WARNING: [],
        #         SeverityLevel.INFO: []
        #     }
            
        #     for issue in category_issues:
        #         by_severity[issue.severity].append(issue)

        #     # Стили для разных уровней серьезности
        #     severity_styles = {
        #         SeverityLevel.CRITICAL: "bold red",
        #         SeverityLevel.WARNING: "bold yellow",
        #         SeverityLevel.INFO: "bold blue"
        #     }

        #     for severity, issues_list in by_severity.items():
        #         if not issues_list:
        #             continue

        #         security_table = Table(
        #             show_header=True,
        #             header_style=severity_styles[severity],
        #             title=f"{severity.value}"
        #         )
                
        #         security_table.add_column("Описание", width=30)
        #         security_table.add_column("Детали", width=50)
        #         security_table.add_column("Рекомендации", width=40)

        #         for issue in issues_list:
        #             security_table.add_row(
        #                 issue.description,
        #                 Text(issue.details, overflow="fold"),
        #                 Text(issue.recommendation or "Нет рекомендаций", overflow="fold")
        #             )

        #         console.print(security_table)
        #         console.print()

    def _print_signature_info(self, sign_info):
        """Вывести информацию о подписи"""
        if not sign_info:
            return
            
        console.print("\n[bold magenta]Информация о подписи:[/bold magenta]")
        
        # Основная информация о подписи
        sign_table = Table(show_header=True, header_style="bold cyan", title="Основная информация о подписи")
        sign_table.add_column("Параметр")
        sign_table.add_column("Значение")
        
        sign_table.add_row("Статус", str(sign_info.status))
        sign_table.add_row("Тип", str(sign_info.sign_type))
        if sign_info.timestamp:
            sign_table.add_row("Временная метка", sign_info.timestamp)
            
        console.print(sign_table)
        console.print()
        
        # Информация о разработчике
        if sign_info.developer_info:
            dev_table = Table(show_header=True, header_style="bold yellow", title="Информация о разработчике")
            dev_table.add_column("Параметр")
            dev_table.add_column("Значение")
            
            for key, value in sign_info.developer_info.items():
                dev_table.add_row(key, value)
                
            console.print(dev_table)
            console.print()
            
        # Анализ entitlements
        if sign_info.analyzed_entitlements:
            console.print("\n[bold magenta]Анализ разрешений:[/bold magenta]")
            
            for category, items in sign_info.analyzed_entitlements.items():
                if items:  # Показываем только непустые категории
                    entitlements_table = Table(show_header=True, header_style="bold green", title=category.upper())
                    entitlements_table.add_column("Разрешение")
                    entitlements_table.add_column("Значение")
                    
                    for key, value in items[:5]:  # Показываем первые 5 элементов
                        if isinstance(value, (list, dict)):
                            entitlements_table.add_row(key, "[complex value]")
                        else:
                            entitlements_table.add_row(key, str(value))
                            
                    console.print(entitlements_table)
                    if len(items) > 5:
                        console.print(f"[dim]... и еще {len(items) - 5} разрешений[/dim]")
                    console.print()

    def _print_symbol_info(self, symbols, libraries):
        """Вывести информацию о символах и библиотеках"""
        if not symbols and not libraries:
            return
            
        console.print("\n[bold magenta]Анализ символов и библиотек:[/bold magenta]")
        
        # Статистика символов
        symbol_stats = {
            SymbolType.LOCAL: 0,
            SymbolType.GLOBAL: 0,
            SymbolType.WEAK: 0,
            SymbolType.UNDEFINED: 0,
            SymbolType.UNKNOWN: 0
        }
        
        for symbol in symbols:
            symbol_stats[symbol.type] += 1
            
        stats_table = Table(show_header=True, header_style="bold cyan", title="Статистика символов")
        stats_table.add_column("Тип")
        stats_table.add_column("Количество")
        
        for sym_type, count in symbol_stats.items():
            if count > 0:  # Показываем только ненулевые значения
                stats_table.add_row(sym_type.value, str(count))
                
        console.print(stats_table)
        console.print()
        
        # Динамические библиотеки
        if libraries:
            lib_table = Table(show_header=True, header_style="bold yellow", title="Динамические библиотеки")
            lib_table.add_column("Библиотека")
            lib_table.add_column("Тип")
            lib_table.add_column("Путь")
            
            for lib in libraries:
                lib_type = []
                if lib.is_system:
                    lib_type.append("System")
                if lib.is_private:
                    lib_type.append("Private")
                if lib.is_weak:
                    lib_type.append("Weak")
                if lib.is_reexported:
                    lib_type.append("Reexported")
                    
                lib_table.add_row(
                    lib.name,
                    ", ".join(lib_type) if lib_type else "-",
                    lib.path or "Не найден"
                )
                
            console.print(lib_table)
            console.print()
            
        # Импортируемые символы
        imported = [s for s in symbols if s.is_undefined]
        if imported:
            import_table = Table(show_header=True, header_style="bold green", title="Импортируемые символы")
            import_table.add_column("Символ")
            import_table.add_column("Библиотека")
            import_table.add_column("Тип")
            
            for symbol in imported[:10]:  # Показываем первые 10 символов
                import_table.add_row(
                    symbol.name,
                    symbol.library or "-",
                    "Weak" if symbol.is_weak else "Strong"
                )
                
            console.print(import_table)
            if len(imported) > 10:
                console.print(f"[dim]... и еще {len(imported) - 10} символов[/dim]")
            console.print()
            
        # Экспортируемые символы
        exported = [s for s in symbols if s.is_exported]
        if exported:
            export_table = Table(show_header=True, header_style="bold blue", title="Экспортируемые символы")
            export_table.add_column("Символ")
            export_table.add_column("Адрес")
            export_table.add_column("Секция")
            export_table.add_column("Флаги")
            
            for symbol in exported[:10]:  # Показываем первые 10 символов
                export_table.add_row(
                    symbol.name,
                    hex(symbol.address) if symbol.address else "-",
                    symbol.section or "-",
                    symbol.export_flags or "-"
                )
                
            console.print(export_table)
            if len(exported) > 10:
                console.print(f"[dim]... и еще {len(exported) - 10} символов[/dim]")
            console.print()

    def _print_embedded_data(self, data: List[EmbeddedData]):
        """Вывод информации о встроенных данных"""
        if not data:
            print("\nВстроенные данные не обнаружены")
            return
            
        print("\nВстроенные данные:")
        
        # Группируем данные по типу
        data_by_type = {}
        for item in data:
            if item.data_type not in data_by_type:
                data_by_type[item.data_type] = []
            data_by_type[item.data_type].append(item)
            
        # Выводим данные по группам
        for data_type, items in data_by_type.items():
            print(f"\n{data_type} ({len(items)}):")
            for item in items:
                print(f"  Секция: {item.section}")
                print(f"  Смещение: 0x{item.offset:x}")
                print(f"  Размер: {item.size} байт")
                if isinstance(item.content, bytes):
                    content = item.content.hex()[:100] + "..." if len(item.content) > 50 else item.content.hex()
                else:
                    content = item.content
                print(f"  Содержимое: {content}")
                print()

    def _print_permissions_info(self, permissions):
        """Вывести информацию о разрешениях"""
        if not permissions:
            return
            
        console.print("\n[bold magenta]Разрешения:[/bold magenta]")
        
        # Группируем разрешения по категориям
        categories = {
            "SECURITY_SENSITIVE": [],
            "HARDWARE_ACCESS": [],
            "DATA_ACCESS": [],
            "NETWORK": [],
            "DEVELOPMENT": [],
            "OTHER": []
        }
        
        for perm, value in permissions.items():
            if any(x in perm.lower() for x in ["security", "protection", "sandbox"]):
                categories["SECURITY_SENSITIVE"].append((perm, value))
            elif any(x in perm.lower() for x in ["camera", "microphone", "bluetooth", "usb"]):
                categories["HARDWARE_ACCESS"].append((perm, value))
            elif any(x in perm.lower() for x in ["location", "contacts", "photos", "calendar"]):
                categories["DATA_ACCESS"].append((perm, value))
            elif any(x in perm.lower() for x in ["network", "internet", "outgoing"]):
                categories["NETWORK"].append((perm, value))
            elif any(x in perm.lower() for x in ["development", "debug", "test"]):
                categories["DEVELOPMENT"].append((perm, value))
            else:
                categories["OTHER"].append((perm, value))
                
        for category, items in categories.items():
            if items:  # Показываем только непустые категории
                perm_table = Table(show_header=True, header_style="bold green", title=category)
                perm_table.add_column("Разрешение")
                perm_table.add_column("Значение")
                
                for perm, value in items:
                    if isinstance(value, (list, dict)):
                        perm_table.add_row(perm, "[complex value]")
                    else:
                        perm_table.add_row(perm, str(value))
                        
                console.print(perm_table)
                console.print()

    def _print_debug_info(self, debug_info):
        """Вывести информацию об отладке"""
        console.print("\n[bold magenta]Анализ отладочной информации:[/bold magenta]")
        
        debug_table = Table(show_header=True, header_style="bold cyan", title="Отладочная информация")
        debug_table.add_column("Параметр")
        debug_table.add_column("Значение")
        
        debug_table.add_row(
            "DWARF информация",
            "[green]Присутствует[/green]" if debug_info.has_dwarf else "[red]Отсутствует[/red]"
        )
        debug_table.add_row(
            "Отладочные символы",
            "[green]Присутствуют[/green]" if debug_info.has_debug_symbols else "[red]Отсутствуют[/red]"
        )
        
        if debug_info.dsym_uuid:
            debug_table.add_row("UUID dSYM", debug_info.dsym_uuid)
            
        console.print(debug_table)
        
        if debug_info.debug_sections:
            sections_table = Table(show_header=True, header_style="bold yellow", title="Секции отладочной информации")
            sections_table.add_column("Имя секции")
            
            for section in debug_info.debug_sections:
                sections_table.add_row(section)
                
            console.print(sections_table)
            
        if debug_info.source_files:
            files_table = Table(show_header=True, header_style="bold green", title="Найденные исходные файлы")
            files_table.add_column("Путь к файлу")
            
            for file in debug_info.source_files[:10]:  # Показываем первые 10 файлов
                files_table.add_row(file)
                
            console.print(files_table)
            if len(debug_info.source_files) > 10:
                console.print(f"[dim]... и еще {len(debug_info.source_files) - 10} файлов[/dim]")

    def analyze(self):
        """Полный анализ файла"""
        self._print_file_info()
        
        headers = self.header_analyzer.analyze()
        
        for i, header in enumerate(headers, 1):
            if len(headers) > 1:
                console.print(f"\n[bold green]Архитектура {i} из {len(headers)}: {header['cpu_type']}[/bold green]")
            
            self._print_header_info(header['header'])
            self._print_segments_info(header['segments'])
            
            # Анализ безопасности
            security_issues = self.security_analyzer.analyze(header['header'])
            self._print_security_info(security_issues)
            
            # Анализ символов
            symbols, libraries = self.symbol_analyzer.analyze()
            self._print_symbol_info(symbols, libraries)
            
            # Анализ встроенных данных
            embedded_data = self.embedded_data_analyzer.analyze()
            self._print_embedded_data(embedded_data)
            
            # Анализ подписи
            sign_info = self.sign_analyzer.analyze()
            self._print_signature_info(sign_info)
            
            # Анализ разрешений
            permissions = self.permission_analyzer.analyze()
            self._print_permissions_info(permissions)
            
            # Анализ отладочной информации
            debug_info = self.debug_analyzer.analyze()
            self._print_debug_info(debug_info)

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
                analyzer._print_file_info()
                headers = analyzer.header_analyzer.analyze()
                
                if args.headers:
                    for i, header in enumerate(headers, 1):
                        if len(headers) > 1:
                            console.print(f"\n[bold green]Архитектура {i} из {len(headers)}: {header['cpu_type']}[/bold green]")
                        analyzer._print_header_info(header['header'])
                
                if args.segments:
                    for i, header in enumerate(headers, 1):
                        if len(headers) > 1:
                            console.print(f"\n[bold green]Архитектура {i} из {len(headers)}: {header['cpu_type']}[/bold green]")
                        analyzer._print_segments_info(header['segments'])
                
                if args.security:
                    for i, header in enumerate(headers, 1):
                        if len(headers) > 1:
                            console.print(f"\n[bold green]Архитектура {i} из {len(headers)}: {header['cpu_type']}[/bold green]")
                            security_issues = analyzer.security_analyzer.analyze(header['header'])
                            analyzer._print_security_info(security_issues)
            else:
                analyzer.analyze()
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main() 