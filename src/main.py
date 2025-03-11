#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import argparse
import sys
from datetime import datetime
from core.header_analyzer import HeaderAnalyzer
from core.constants import FLAG_DESCRIPTIONS
from typing import Optional
import os
#from tabulate import tabulate

console = Console()

class MachOAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.header_analyzer = HeaderAnalyzer(file_path)

    def _print_file_info(self):
        """Вывести базовую информацию о файле"""
        size, mtime = self.header_analyzer.get_file_info()
        console.print(Panel(f"[bold blue]Файл:[/bold blue] {self.file_path}"))
        console.print(f"[bold green]Размер:[/bold green] {size / 1024:.2f} Кб ({size} байт)")
        console.print(f"[bold green]Дата модификации:[/bold green] {mtime.strftime('%Y-%m-%d %H:%M:%S')}\n")

    def _print_header_info(self, header):
        """Вывести информацию о заголовках"""
        # Основная информация
        basic_table = Table(show_header=True, header_style="bold magenta", title="Основная информация")
        basic_table.add_column("Параметр")
        basic_table.add_column("Значение")
        
        basic_table.add_row("Magic", header.magic)
        basic_table.add_row("Битность", "64-bit" if header.is_64_bit else "32-bit")
        basic_table.add_row("CPU Type", header.cpu_type)
        basic_table.add_row("CPU Subtype", header.cpu_subtype)
        basic_table.add_row("Тип файла", header.file_type)
        basic_table.add_row("Количество команд", str(header.ncmds))
        basic_table.add_row("Размер команд", f"{header.sizeofcmds} байт")
        if header.reserved != 0:
            basic_table.add_row("Reserved", str(header.reserved))
        console.print(basic_table)
        console.print()

        # Версии и идентификаторы
        version_table = Table(show_header=True, header_style="bold cyan", title="Версии и идентификаторы")
        version_table.add_column("Параметр")
        version_table.add_column("Значение")
        
        if header.uuid:
            version_table.add_row("UUID", header.uuid)
        if header.min_version:
            version_table.add_row("Минимальная версия OS", header.min_version)
        if header.sdk_version:
            version_table.add_row("Версия SDK", header.sdk_version)
        if header.source_version:
            version_table.add_row("Версия исходного кода", header.source_version)
        if header.build_version:
            version_table.add_row("Версия сборки", header.build_version)
        
        if version_table.row_count > 0:
            console.print(version_table)
            console.print()

        # Флаги
        flags_table = Table(show_header=True, header_style="bold yellow", title="Флаги")
        flags_table.add_column("Флаг")
        flags_table.add_column("Описание")
        
        if header.flags:
            for flag in header.flags:
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
        summary_table.add_column("Смещение в файле")
        summary_table.add_column("Размер в файле")
        summary_table.add_column("Max Prot")
        summary_table.add_column("Init Prot")
        summary_table.add_column("Кол-во секций")
        summary_table.add_column("Флаги")



        for segment in segments:
            summary_table.add_row(
                segment.name, 
                hex(segment.vm_address), 
                f"{segment.vm_size:,} байт", 
                str(segment.file_offset), 
                f"{segment.file_size:,} байт", 
                segment.max_prot, 
                segment.init_prot, 
                str(len(segment.sections)),
                ", ".join(segment.flags)
            )
        console.print(summary_table)


        console.print("\n[bold magenta]Сегменты и секции:[/bold magenta]")
        
        for segment in segments:
            # Таблица сегмента
            # segment_table = Table(show_header=True, header_style="bold cyan", title=f"Сегмент {segment.name}")
            # segment_table.add_column("Параметр")
            # segment_table.add_column("Значение")
            
            # segment_table.add_row("VM адрес", hex(segment.vm_address))
            # segment_table.add_row("VM размер", f"{segment.vm_size:,} байт")
            # segment_table.add_row("Смещение в файле", str(segment.file_offset))
            # segment_table.add_row("Размер в файле", f"{segment.file_size:,} байт")
            # segment_table.add_row("Максимальная защита", segment.max_prot)
            # segment_table.add_row("Начальная защита", segment.init_prot)
            # if segment.flags:
            #     segment_table.add_row("Флаги", ", ".join(segment.flags))
                
            # console.print(segment_table)
            # console.print()
            
            # Таблица секций
            if segment.sections:
                sections_table = Table(show_header=True, header_style="bold green", title=f"Секции в {segment.name}")
                sections_table.add_column("Имя")
                sections_table.add_column("Адрес")
                sections_table.add_column("Размер")
                sections_table.add_column("Тип")
                sections_table.add_column("Флаги")
                
                for section in segment.sections:
                    sections_table.add_row(
                        section.name,
                        hex(section.address),
                        f"{section.size:,}",
                        section.type,
                        ", ".join(section.flags) if section.flags else "-"
                    )
                
                console.print(sections_table)
                console.print()

    def analyze(self):
        """Основной метод анализа файла"""
        try:
            self._print_file_info()
            headers = self.header_analyzer.analyze_headers()
            
            if len(headers) > 1:
                console.print("[bold yellow]Найдены несколько архитектур:[/bold yellow]")

            for i, header in enumerate(headers, 1):
                if len(headers) > 1:
                    console.print(f"\n[bold green]Архитектура {i} из {len(headers)}: {header.cpu_type}[/bold green]")
                self._print_header_info(header)
                self._print_segments_info(header.segments)

        except Exception as e:
            console.print(f"[red]Ошибка при анализе файла: {str(e)}[/red]")
            raise

def main():
    parser = argparse.ArgumentParser(description='MachO File Analyzer')
    parser.add_argument('file', help='Path to MachO file to analyze')
    parser.add_argument('--headers', action='store_true', help='Show file headers')
    parser.add_argument('--segments', action='store_true', help='Show segments and sections')
    parser.add_argument('--imports', action='store_true', help='Show imports')
    parser.add_argument('--exports', action='store_true', help='Show exports')
    parser.add_argument('--security', action='store_true', help='Check security mechanisms')
    parser.add_argument('--patterns', action='store_true', help='Search for known patterns')
    parser.add_argument('--debug-info', action='store_true', help='Check for debug information')
    
    args = parser.parse_args()

    try:
        analyzer = MachOAnalyzer(args.file)
        analyzer.analyze()
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main() 