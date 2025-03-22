from typing import List, Dict, Optional
from macholib.MachO import MachO
from macholib.mach_o import *
import os
import struct

# Константы для STABS
N_GSYM = 0x20    # Global symbol
N_STSYM = 0x26   # Static symbol
N_SO = 0x64      # Source file name
N_SOL = 0x84     # Source file name (include file)
N_FUN = 0x24     # Function name

# Важные секции DWARF
DWARF_SECTIONS = [
    '__debug_info',    # Основная отладочная информация
    '__debug_abbrev',  # Аббревиатуры для __debug_info
    '__debug_line',    # Информация о строках кода
    '__debug_str',     # Строковая таблица
    '__debug_ranges',  # Диапазоны адресов
    '__debug_frame'    # Информация о кадрах стека
]

# Символы защиты
PROTECTION_SYMBOLS = [
    '___stack_chk_guard',  # Stack canary guard
    '___stack_chk_fail',   # Stack canary failure handler
]

# Отладочные символы
DEBUG_SYMBOLS = [
    '__dbg_',         # Общие отладочные символы
    '__asan_',        # Address Sanitizer
    '__ubsan_',       # Undefined Behavior Sanitizer
    '__gdb_',         # GDB specific symbols
    '_objc_debug',    # Objective-C debug symbols
    '__lldb_',        # LLDB debugger symbols
    '__debug_',       # Generic debug symbols
    '_DWARF',         # DWARF debug symbols
    '__DWARF',        # DWARF sections
]

# Системные символы динамического линковщика
DYNAMIC_SYMBOLS = [
    'dladdr',         # Dynamic linker info
    'dlsym',          # Dynamic linker symbol lookup
    'dlopen',         # Dynamic linker loading
    'backtrace',      # Stack trace utility
]

class DebugInfo:
    """Информация об отладочных данных в файле"""
    def __init__(self):
        self.has_dwarf: bool = False
        self.has_debug_symbols: bool = False
        self.has_stabs: bool = False
        self.debug_sections: List[str] = []
        self.source_files: List[str] = []
        self.debug_symbols: List[str] = []
        self.protection_symbols: List[str] = []  # Новое поле для символов защиты
        self.dsym_uuid: Optional[str] = None
        self.functions: List[str] = []
        self.includes: List[str] = []
        self.dwarf_details: Dict[str, bool] = {sect.strip('_'): False for sect in DWARF_SECTIONS}
        self.has_dwarf_info: bool = False

class DebugAnalyzer:
    def __init__(self, macho: MachO, file_path: str):
        self.macho = macho
        self.file_path = file_path
        
    def analyze(self) -> DebugInfo:
        """Анализ отладочной информации в файле"""
        debug_info = DebugInfo()
        
        # Анализ секций
        self._analyze_debug_sections(debug_info)
        
        # Анализ символов
        self._analyze_debug_symbols(debug_info)
        
        # Проверка dSYM
        self._check_dsym(debug_info)
        
        # Устанавливаем has_dwarf_info на основе наличия DWARF секций
        debug_info.has_dwarf_info = any(debug_info.dwarf_details.values())
        
        return debug_info
    
    def _analyze_debug_sections(self, debug_info: DebugInfo):
        """Анализ секций с отладочной информацией"""
        for header in self.macho.headers:
            for cmd in header.commands:
                if not hasattr(cmd[0], 'cmd'):
                    continue
                    
                if cmd[0].cmd in [LC_SEGMENT_64, LC_SEGMENT]:
                    segment = cmd[1]
                    if not hasattr(segment, 'segname'):
                        continue
                        
                    segname = segment.segname.decode('utf-8').strip('\x00')
                    if segname == '__DWARF':
                        if hasattr(segment, 'sections'):
                            dwarf_found = False
                            for sect in segment.sections:
                                if hasattr(sect[0], 'sectname'):
                                    sectname = sect[0].sectname.decode('utf-8').strip('\x00')
                                    debug_info.debug_sections.append(sectname)
                                    
                                    # Проверяем наличие важных секций DWARF
                                    if sectname in DWARF_SECTIONS:
                                        dwarf_found = True
                                        debug_info.dwarf_details[sectname.strip('_')] = True
                                        
                                        # Анализируем размер секции
                                        if hasattr(sect[0], 'size') and sect[0].size > 0:
                                            debug_info.has_dwarf = True
    
    def _analyze_debug_symbols(self, debug_info: DebugInfo):
        """Анализ отладочных символов и STABS"""
        symtab = None
        strtab = None
        
        # Находим таблицы символов и строк
        for header in self.macho.headers:
            for cmd in header.commands:
                if not hasattr(cmd[0], 'cmd'):
                    continue
                    
                if cmd[0].cmd == LC_SYMTAB:
                    symtab = cmd[1]
            
        if not symtab or not hasattr(symtab, 'symoff') or not hasattr(symtab, 'stroff'):
            return
            
        # Читаем символы
        with open(self.file_path, 'rb') as f:
            # Читаем таблицу строк
            f.seek(symtab.stroff)
            strtab_data = f.read(symtab.strsize)
            
            # Читаем символы
            f.seek(symtab.symoff)
            for _ in range(symtab.nsyms):
                try:
                    # В зависимости от битности, размер структуры разный
                    if self.macho.headers[0].header.magic in (MH_MAGIC_64, MH_CIGAM_64):
                        # nlist_64: struct { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; }
                        fmt = '<IBBHQ' if self.macho.headers[0].header.magic in (MH_MAGIC, MH_CIGAM) else '>IBBHQ'
                        size = 16
                    else:
                        # nlist: struct { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; int16_t n_desc; uint32_t n_value; }
                        fmt = '<IBBhI' if self.macho.headers[0].header.magic in (MH_MAGIC, MH_CIGAM) else '>IBBhI'
                        size = 12
                        
                    nlist_data = f.read(size)
                    if not nlist_data or len(nlist_data) != size:
                        break
                        
                    # Распаковываем структуру
                    unpacked = struct.unpack(fmt, nlist_data)
                    strx, n_type = unpacked[0], unpacked[1]
                    
                    # Получаем имя символа
                    try:
                        if strx < len(strtab_data):
                            end = strtab_data.index(b'\x00', strx)
                            name = strtab_data[strx:end].decode('utf-8')
                            
                            # Проверяем на символы защиты
                            if any(prot_sym in name for prot_sym in PROTECTION_SYMBOLS):
                                debug_info.protection_symbols.append(name)
                                continue  # Пропускаем дальнейшие проверки для этого символа
                            
                            # Проверяем на отладочные символы
                            if any(debug_sym in name for debug_sym in DEBUG_SYMBOLS):
                                debug_info.has_debug_symbols = True
                                debug_info.debug_symbols.append(name)
                            
                            # Проверяем, что это отладочный символ (STABS)
                            if n_type & N_STAB:
                                debug_info.has_stabs = True
                                debug_info.has_debug_symbols = True
                                
                                # Обрабатываем разные типы STABS
                                if n_type == N_SO:  # Исходный файл
                                    if name and name.endswith(('.c', '.cpp', '.m', '.mm', '.swift')):
                                        debug_info.source_files.append(name)
                                elif n_type == N_SOL:  # Include файл
                                    if name:
                                        debug_info.includes.append(name)
                                elif n_type == N_FUN:  # Функция
                                    if name:
                                        # Убираем параметры функции, если они есть
                                        func_name = name.split('(')[0]
                                        debug_info.functions.append(func_name)
                                elif n_type in (N_GSYM, N_STSYM):  # Глобальные и статические символы
                                    if name:
                                        debug_info.debug_symbols.append(name)
                    except (ValueError, UnicodeDecodeError):
                        continue
                except struct.error:
                    continue
    
    def _check_dsym(self, debug_info: DebugInfo):
        """Проверка наличия отдельного файла с отладочной информацией"""
        for header in self.macho.headers:
            for cmd in header.commands:
                if not hasattr(cmd[0], 'cmd'):
                    continue
                    
                if cmd[0].cmd == LC_UUID and hasattr(cmd[1], 'uuid'):
                    try:
                        # Проверяем, что uuid действительно байтовый
                        if isinstance(cmd[1].uuid, bytes) and len(cmd[1].uuid) == 16:
                            debug_info.dsym_uuid = ''.join(['%02X' % x for x in cmd[1].uuid])
                            
                            # Проверяем наличие dSYM в стандартных местах
                            dsym_paths = [
                                f"{self.file_path}.dSYM",
                                f"{self.file_path}.dSYM/Contents/Resources/DWARF/{os.path.basename(self.file_path)}",
                                # Дополнительные места для поиска dSYM
                                os.path.join(os.path.dirname(self.file_path), "*.dSYM"),
                                "/Library/Developer/Xcode/DerivedData/*/Build/Products/Debug/*.dSYM"
                            ]
                            
                            for path in dsym_paths:
                                if '*' in path:  # Если путь содержит wildcard
                                    import glob
                                    matching_paths = glob.glob(path)
                                    for match in matching_paths:
                                        if os.path.exists(match):
                                            debug_info.has_dwarf = True
                                            return
                                elif os.path.exists(path):
                                    debug_info.has_dwarf = True
                                    return
                    except (AttributeError, TypeError, ValueError) as e:
                        # Пропускаем ошибки при обработке UUID
                        continue 