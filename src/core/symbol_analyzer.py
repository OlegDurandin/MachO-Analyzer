from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Tuple
from macholib.mach_o import *
import struct
import os


class SymbolType(Enum):
    """Типы символов"""
    LOCAL = "Local"
    GLOBAL = "Global"
    WEAK = "Weak"
    UNDEFINED = "Undefined"
    UNKNOWN = "Unknown"


@dataclass
class Symbol:
    """Информация о символе"""
    name: str
    type: SymbolType
    section: Optional[str]
    address: Optional[int]
    is_weak: bool
    is_undefined: bool
    library: Optional[str] = None  # Для импортируемых символов
    is_exported: bool = False  # Флаг экспорта
    export_flags: Optional[str] = None  # Флаги экспорта


@dataclass
class LibraryInfo:
    """Информация о библиотеке"""
    name: str
    is_system: bool
    is_private: bool
    is_weak: bool
    is_reexported: bool
    path: Optional[str] = None


class SymbolAnalyzer:
    """Анализатор символов и импортов Mach-O файлов"""
    
    def __init__(self, macho_file, file_path: str):
        self.macho = macho_file
        self.file_path = file_path
        self.system_paths = [
            '/usr/lib/',
            '/System/Library/',
            '/Library/',
            '/usr/local/lib/'
        ]
        
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
        
    def _get_symbol_type(self, n_type: int, n_desc: int) -> Tuple[SymbolType, bool, bool, bool, Optional[str]]:
        """Определение типа символа на основе n_type и n_desc"""
        is_weak = bool(n_desc & N_WEAK_DEF)
        is_undefined = bool(n_desc & N_WEAK_REF)
        is_exported = bool(n_type & N_EXT) and not bool(n_type & N_PEXT)  # Экспортируемый, но не приватный
        export_flags = []
        
        # Пропускаем отладочные символы
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
        
        for cmd in header.commands:
            if cmd[0].cmd == LC_SYMTAB:
                symtab = cmd[1]
                strtab = None
                
                # Находим таблицу строк
                for str_cmd in header.commands:
                    if str_cmd[0].cmd == LC_SYMTAB:
                        strtab = str_cmd[1]
                        break
                        
                if not strtab:
                    continue
                    
                # Читаем таблицу символов
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
                            
                        # Получаем имя символа
                        if n_strx == 0:  # Пропускаем пустые символы
                            continue
                            
                        # Ищем конец строки в таблице строк
                        end_pos = string_table.find(b'\x00', n_strx)
                        if end_pos == -1:
                            end_pos = len(string_table)
                            
                        try:
                            # Пробуем декодировать как UTF-8
                            name = string_table[n_strx:end_pos].decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                # Если не получилось, пробуем как ASCII
                                name = string_table[n_strx:end_pos].decode('ascii', errors='replace')
                            except UnicodeDecodeError:
                                # Если и это не получилось, пропускаем символ
                                continue
                        
                        # Определяем тип символа
                        sym_type, is_weak, is_undefined, is_exported, export_flags = self._get_symbol_type(n_type, n_desc)
                        
                        # Получаем имя секции
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
                        
        return symbols
        
    def _get_dynamic_libraries(self, header) -> List[LibraryInfo]:
        """Получение списка динамических библиотек с информацией о безопасности"""
        libraries = []
        
        for cmd in header.commands:
            cmd_type = cmd[0].cmd
            if cmd_type in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                dylib = cmd[2]
                name = dylib.decode('utf-8').rstrip('\x00')
                
                # Определяем флаги библиотеки
                is_weak = bool(cmd_type == LC_LOAD_WEAK_DYLIB)
                is_reexported = bool(cmd_type == LC_REEXPORT_DYLIB)
                
                # Получаем полный путь
                path = self._get_library_path(name)
                
                libraries.append(LibraryInfo(
                    name=name,
                    is_system=self._is_system_library(name),
                    is_private=self._is_private_library(name),
                    is_weak=is_weak,
                    is_reexported=is_reexported,
                    path=path
                ))
                
        return libraries
        
    def analyze(self) -> Tuple[List[Symbol], List[LibraryInfo]]:
        """Анализ символов и импортов"""
        symbols = []
        libraries = []
        
        for header in self.macho.headers:
            symbols.extend(self._parse_symbol_table(header))
            libraries.extend(self._get_dynamic_libraries(header))
            
        return symbols, libraries 