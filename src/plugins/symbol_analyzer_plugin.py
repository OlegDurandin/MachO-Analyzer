from typing import Dict, Any, List, Optional
from core.plugin_base import MachOPlugin
from core.symbol_analyzer import Symbol, SymbolType, LibraryInfo
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from macholib.mach_o import (
    LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB, LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, MH_MAGIC, MH_CIGAM,
    MH_MAGIC_64, MH_CIGAM_64, N_STAB, N_PEXT, N_EXT,
    N_WEAK_DEF, N_WEAK_REF, N_SYMBOL_RESOLVER, N_REF_TO_WEAK
)
import struct
import os

console = Console()

class SymbolAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа символов в Mach-O файле"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        
        # Системные пути для поиска библиотек
        self.system_paths = [
            '/usr/lib/',
            '/System/Library/',
            '/Library/',
            '/usr/local/lib/'
        ]
    
    def analyze(self) -> tuple[List[Symbol], List[LibraryInfo]]:
        """Анализирует символы в Mach-O файле"""
        symbols = []
        libraries = []
        
        try:
            for header in self.macho.headers:
                # Анализ символов
                symbols.extend(self._parse_symbol_table(header))
                
                # Анализ библиотек
                libraries.extend(self._get_dynamic_libraries(header))
                
        except Exception as e:
            console.print(f"[red]Ошибка при анализе символов: {str(e)}[/red]")
            
        return symbols, libraries
    
    def _print_symbol_info(self, symbols: List[Symbol], libraries: List[LibraryInfo]) -> None:
        """Выводит информацию о символах и библиотеках"""
        try:
            # Основная информация
            console.print("\n[bold magenta]Основная информация о символах и библиотеках[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            # Подсчитываем статистику
            total_symbols = len(symbols)
            global_symbols = sum(1 for s in symbols if s.type == SymbolType.GLOBAL)
            local_symbols = sum(1 for s in symbols if s.type == SymbolType.LOCAL)
            undefined_symbols = sum(1 for s in symbols if s.is_undefined)
            weak_symbols = sum(1 for s in symbols if s.is_weak)
            exported_symbols = sum(1 for s in symbols if s.is_exported)
            
            total_libraries = len(libraries)
            system_libraries = sum(1 for l in libraries if l.is_system)
            private_libraries = sum(1 for l in libraries if l.is_private)
            weak_libraries = sum(1 for l in libraries if l.is_weak)
            reexported_libraries = sum(1 for l in libraries if l.is_reexported)
            
            basic_rows = [
                ["Всего символов", str(total_symbols)],
                ["Глобальных", str(global_symbols)],
                ["Локальных", str(local_symbols)],
                ["Неопределенных", str(undefined_symbols)],
                ["Слабых", str(weak_symbols)],
                ["Экспортируемых", str(exported_symbols)],
                ["Всего библиотек", str(total_libraries)],
                ["Системных", str(system_libraries)],
                ["Приватных", str(private_libraries)],
                ["Слабых", str(weak_libraries)],
                ["Реэкспортируемых", str(reexported_libraries)]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Символы
            if symbols:
                console.print("\n[bold cyan]Символы[/bold cyan]")
                symbol_table = Table(show_header=True, header_style="bold cyan")
                symbol_table.add_column("Имя", style="cyan")
                symbol_table.add_column("Тип", style="green")
                symbol_table.add_column("Секция", style="yellow")
                symbol_table.add_column("Адрес", style="white")
                symbol_table.add_column("Флаги", style="red")
                
                for sym in symbols:
                    flags = []
                    if sym.is_weak:
                        flags.append("Weak")
                    if sym.is_undefined:
                        flags.append("Undefined")
                    if sym.is_exported:
                        flags.append("Exported")
                    
                    symbol_table.add_row(
                        sym.name,
                        sym.type.value,
                        sym.section or "N/A",
                        hex(sym.address) if sym.address else "N/A",
                        ", ".join(flags) if flags else "N/A"
                    )
                console.print(symbol_table)
            
            # Библиотеки
            if libraries:
                console.print("\n[bold yellow]Библиотеки[/bold yellow]")
                library_table = Table(show_header=True, header_style="bold yellow")
                library_table.add_column("Имя", style="cyan")
                library_table.add_column("Тип", style="green")
                library_table.add_column("Флаги", style="red")
                library_table.add_column("Путь", style="white")
                
                for lib in libraries:
                    flags = []
                    if lib.is_weak:
                        flags.append("Weak")
                    if lib.is_reexported:
                        flags.append("Reexported")
                    
                    library_table.add_row(
                        lib.name,
                        "Системная" if lib.is_system else "Пользовательская",
                        ", ".join(flags) if flags else "N/A",
                        lib.path or "N/A"
                    )
                console.print(library_table)
                
        except Exception as e:
            console.print(f"[red]Ошибка при выводе информации о символах: {str(e)}[/red]")
    
    def _is_system_library(self, name: str) -> bool:
        """Проверка является ли библиотека системной"""
        return any(name.startswith(path) for path in self.system_paths)
    
    def _is_private_library(self, name: str) -> bool:
        """Проверка является ли библиотека приватной"""
        return '/private/' in name or name.startswith('@rpath/')
    
    def _get_library_path(self, name: str) -> Optional[str]:
        """Получение полного пути к библиотеке"""
        if name.startswith('@rpath/'):
            return name
        if os.path.exists(name):
            return name
        for path in self.system_paths:
            full_path = os.path.join(path, name)
            if os.path.exists(full_path):
                return full_path
        return None
    
    def _get_symbol_type(self, n_type: int, n_desc: int) -> tuple[SymbolType, bool, bool, bool, Optional[str]]:
        """Определение типа символа на основе n_type и n_desc"""
        is_weak = bool(n_desc & N_WEAK_DEF)
        is_undefined = bool(n_desc & N_WEAK_REF)
        is_exported = bool(n_type & N_EXT) and not bool(n_type & N_PEXT)
        export_flags = []
        
        if n_type & N_STAB:
            return SymbolType.UNKNOWN, False, False, False, None
            
        if n_desc & N_WEAK_REF:
            export_flags.append("Weak")
        if n_desc & N_SYMBOL_RESOLVER:
            export_flags.append("Resolver")
        if n_desc & N_REF_TO_WEAK:
            export_flags.append("WeakRef")
        if n_type & N_PEXT:
            export_flags.append("Private")
            
        return (SymbolType.GLOBAL if n_type & N_EXT else SymbolType.LOCAL,
                is_weak, is_undefined, is_exported,
                ", ".join(export_flags) if export_flags else None)
    
    def _get_section_name(self, header, sect_idx: int) -> Optional[str]:
        """Получение имени секции по индексу"""
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                for sect in cmd[2]:
                    if sect.reserved1 == sect_idx:
                        return sect.sectname.decode('utf-8').rstrip('\x00')
        return None
    
    def _parse_symbol_table(self, header) -> List[Symbol]:
        """Парсинг таблицы символов"""
        symbols = []
        
        # Находим таблицу символов и строк
        symtab = None
        strtab = None
        
        for cmd in header.commands:
            if cmd[0].cmd == LC_SYMTAB:
                symtab = cmd[1]
                strtab = cmd[1]
                break
                    
        if not symtab or not strtab:
            return symbols
                    
        try:
            with open(self.file_path, 'rb') as f:
                # Читаем таблицу строк
                f.seek(strtab.stroff)
                string_table = f.read(strtab.strsize)
                
                # Читаем таблицу символов
                f.seek(symtab.symoff)
                for i in range(symtab.nsyms):
                    if header.header.magic in (MH_MAGIC, MH_CIGAM):
                        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('<IBBHI', f.read(12))
                    else:
                        n_strx, n_type, n_desc, n_sect, n_value = struct.unpack('<IBBHQ', f.read(16))
                        
                    if n_strx == 0:
                        continue
                        
                    end_pos = string_table.find(b'\x00', n_strx)
                    if end_pos == -1:
                        end_pos = len(string_table)
                        
                    try:
                        name = string_table[n_strx:end_pos].decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            name = string_table[n_strx:end_pos].decode('ascii', errors='replace')
                        except UnicodeDecodeError:
                            continue
                    
                    sym_type, is_weak, is_undefined, is_exported, export_flags = self._get_symbol_type(n_type, n_desc)
                    section = self._get_section_name(header, n_sect) if n_sect > 0 else None
                    
                    symbols.append(Symbol(
                        name=name,
                        type=sym_type,
                        section=section,
                        address=n_value if n_value != 0 else None,
                        is_weak=is_weak,
                        is_undefined=is_undefined,
                        is_exported=is_exported,
                        export_flags=export_flags
                    ))
                    
        except Exception as e:
            console.print(f"[red]Ошибка при чтении таблицы символов: {str(e)}[/red]")
                    
        return symbols
    
    def _get_dynamic_libraries(self, header) -> List[LibraryInfo]:
        """Получение списка динамических библиотек"""
        libraries = []
        
        try:
            for cmd in header.commands:
                cmd_type = cmd[0].cmd
                if cmd_type in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                    try:
                        dylib = cmd[2]
                        if not dylib:
                            continue
                            
                        name = dylib.decode('utf-8').rstrip('\x00')
                        if not name:
                            continue
                            
                        is_weak = bool(cmd_type == LC_LOAD_WEAK_DYLIB)
                        is_reexported = bool(cmd_type == LC_REEXPORT_DYLIB)
                        path = self._get_library_path(name)
                        
                        libraries.append(LibraryInfo(
                            name=name,
                            is_system=self._is_system_library(name),
                            is_private=self._is_private_library(name),
                            is_weak=is_weak,
                            is_reexported=is_reexported,
                            path=path
                        ))
                    except Exception as e:
                        console.print(f"[yellow]Ошибка при обработке библиотеки: {str(e)}[/yellow]")
                        continue
        except Exception as e:
            console.print(f"[red]Ошибка при анализе библиотек: {str(e)}[/red]")
                
        return libraries
    
    @staticmethod
    def get_name() -> str:
        return "symbol_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует символы и библиотеки в Mach-O файле"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 