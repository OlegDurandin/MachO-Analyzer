from dataclasses import dataclass
from datetime import datetime
import os
from typing import List, Optional, Dict, Any
from macholib.MachO import MachO
from macholib.mach_o import *
from .segment_analyzer import SegmentAnalyzer, Segment

from .constants import *

@dataclass
class MachHeaderInfo:
    """Информация о заголовке Mach-O файла"""
    cpu_type: str
    cpu_subtype: str
    file_type: str
    flags: List[str]
    magic: str
    ncmds: int
    sizeofcmds: int
    is_64_bit: bool
    reserved: int  # Зарезервированное поле (обычно 0)
    uuid: Optional[str]  # UUID файла если есть
    min_version: Optional[str]  # Минимальная версия OS
    sdk_version: Optional[str]  # Версия SDK
    source_version: Optional[str]  # Версия исходного кода
    build_version: Optional[str]  # Версия сборки
    segments: List[Segment]

class HeaderAnalyzer:
    """Анализатор заголовков Mach-O файлов"""
    
    def __init__(self, macho):
        self.macho = macho
        self.file_path = macho.filename
        self.segment_analyzer = SegmentAnalyzer(self.macho)
        
    def _get_load_command_data(self, header) -> dict:
        """Получить данные из load commands"""
        result = {
            'uuid': None,
            'min_version': None,
            'sdk_version': None,
            'source_version': None,
            'build_version': None
        }
        
        for cmd in header.commands:
            try:
                cmd_type = cmd[0].cmd
                if cmd_type == LC_UUID:
                    uuid_bytes = getattr(cmd[1], 'uuid', None)
                    if uuid_bytes:
                        result['uuid'] = ''.join(f'{b:02x}' for b in uuid_bytes)
                elif cmd_type == LC_VERSION_MIN_MACOSX:
                    version = cmd[1]
                    result['min_version'] = f"{version.version >> 16}.{(version.version >> 8) & 0xff}.{version.version & 0xff}"
                    result['sdk_version'] = f"{version.sdk >> 16}.{(version.sdk >> 8) & 0xff}.{version.sdk & 0xff}"
                elif cmd_type == LC_SOURCE_VERSION:
                    version = cmd[1].version
                    a = version >> 40
                    b = (version >> 30) & 0x3ff
                    c = (version >> 20) & 0x3ff
                    d = (version >> 10) & 0x3ff
                    e = version & 0x3ff
                    result['source_version'] = f"{a}.{b}.{c}.{d}.{e}"
                elif cmd_type == LC_BUILD_VERSION:
                    version = cmd[1]
                    result['build_version'] = f"{version.minos >> 16}.{(version.minos >> 8) & 0xff}.{version.minos & 0xff}"
            except Exception as e:
                print(f"Ошибка при обработке команды {cmd_type}: {str(e)}")
                continue
        
        return result
        
    def get_file_info(self) -> dict:
        """Получение базовой информации о файле"""
        stats = os.stat(self.file_path)
        return {
            'size': stats.st_size / 1024,  # размер в КБ
            'size_bytes': stats.st_size,    # размер в байтах
            'modification_date': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        }
    
    @staticmethod
    def _get_cpu_type(cputype: int) -> str:
        """Получить тип CPU"""
        cpu_types = {
            CPU_TYPE_X86: "x86",
            CPU_TYPE_X86_64: "x86_64",
            CPU_TYPE_ARM: "arm",
            CPU_TYPE_ARM64: "arm64",
            CPU_TYPE_POWERPC: "powerpc",
            CPU_TYPE_POWERPC64: "powerpc64"
        }
        return cpu_types.get(cputype, f"Unknown ({cputype})")
    
    def _get_file_type(self, filetype: int) -> str:
        """Получить тип файла"""
        file_types = {
            MH_OBJECT: "Object",
            MH_EXECUTE: "Executable",
            MH_FVMLIB: "Fixed VM Library",
            MH_CORE: "Core",
            MH_PRELOAD: "Preloaded",
            MH_DYLIB: "Dynamic Library",
            MH_DYLINKER: "Dynamic Linker",
            MH_BUNDLE: "Bundle",
            MH_DYLIB_STUB: "Dynamic Library Stub",
            MH_DSYM: "Debug Symbols",
        }
        return file_types.get(filetype, f"Unknown ({filetype})")
    
    def _get_flags(self, flags: int) -> List[str]:
        """Получить список флагов"""
        flags_list = []
        if flags & MH_NOUNDEFS:
            flags_list.append("MH_NOUNDEFS")
        if flags & MH_INCRLINK:
            flags_list.append("MH_INCRLINK")
        if flags & MH_DYLDLINK:
            flags_list.append("MH_DYLDLINK")
        if flags & MH_BINDATLOAD:
            flags_list.append("MH_BINDATLOAD")
        if flags & MH_PREBOUND:
            flags_list.append("MH_PREBOUND")
        if flags & MH_SPLIT_SEGS:
            flags_list.append("MH_SPLIT_SEGS")
        if flags & MH_LAZY_INIT:
            flags_list.append("MH_LAZY_INIT")
        if flags & MH_TWOLEVEL:
            flags_list.append("MH_TWOLEVEL")
        if flags & MH_FORCE_FLAT:
            flags_list.append("MH_FORCE_FLAT")
        if flags & MH_NOMULTIDEFS:
            flags_list.append("MH_NOMULTIDEFS")
        if flags & MH_NOFIXPREBINDING:
            flags_list.append("MH_NOFIXPREBINDING")
        if flags & MH_PREBINDABLE:
            flags_list.append("MH_PREBINDABLE")
        if flags & MH_ALLMODSBOUND:
            flags_list.append("MH_ALLMODSBOUND")
        if flags & MH_SUBSECTIONS_VIA_SYMBOLS:
            flags_list.append("MH_SUBSECTIONS_VIA_SYMBOLS")
        if flags & MH_CANONICAL:
            flags_list.append("MH_CANONICAL")
        if flags & MH_WEAK_DEFINES:
            flags_list.append("MH_WEAK_DEFINES")
        if flags & MH_BINDS_TO_WEAK:
            flags_list.append("MH_BINDS_TO_WEAK")
        if flags & MH_ALLOW_STACK_EXECUTION:
            flags_list.append("MH_ALLOW_STACK_EXECUTION")
        if flags & MH_ROOT_SAFE:
            flags_list.append("MH_ROOT_SAFE")
        if flags & MH_SETUID_SAFE:
            flags_list.append("MH_SETUID_SAFE")
        if flags & MH_NO_REEXPORTED_DYLIBS:
            flags_list.append("MH_NO_REEXPORTED_DYLIBS")
        if flags & MH_PIE:
            flags_list.append("MH_PIE")
        if flags & MH_DEAD_STRIPPABLE_DYLIB:
            flags_list.append("MH_DEAD_STRIPPABLE_DYLIB")
        if flags & MH_HAS_TLV_DESCRIPTORS:
            flags_list.append("MH_HAS_TLV_DESCRIPTORS")  
        if flags & MH_NO_HEAP_EXECUTION:
            flags_list.append("MH_NO_HEAP_EXECUTION")
        if flags & MH_APP_EXTENSION_SAFE:
            flags_list.append("MH_APP_EXTENSION_SAFE")
        return flags_list
    
    @staticmethod
    def _get_magic(header) -> str:
        """Получить magic number"""
        magic_numbers = {
            MH_MAGIC: "MH_MAGIC",
            MH_CIGAM: "MH_CIGAM",
            MH_MAGIC_64: "MH_MAGIC_64",
            MH_CIGAM_64: "MH_CIGAM_64",
            FAT_MAGIC: "FAT_MAGIC",
            FAT_CIGAM: "FAT_CIGAM"
        }
        return magic_numbers.get(header.MH_MAGIC, f"Unknown ({header.MH_MAGIC})")
    
    def analyze(self) -> List[Dict]:
        """Анализ всех заголовков"""
        result = []
        for header in self.macho.headers:
            header_info = {
                'header': header,
                'cpu_type': self._get_cpu_type(header.header.cputype),
                'segments': self.segment_analyzer.analyze_segments(header)
            }
            result.append(header_info)
        return result 

    def get_segments(self, header):
        """Получение информации о сегментах"""
        segments = []
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                try:
                    segment = cmd[2]  # Это сегмент
                    segments.append({
                        'name': cmd[1].segname.decode('utf-8').strip('\x00'),
                        'vm_address': cmd[1].vmaddr,
                        'vm_size': cmd[1].vmsize,
                        'file_offset': cmd[1].fileoff,
                        'file_size': cmd[1].filesize,
                        'max_prot': self._get_protection_flags(cmd[1].maxprot),
                        'init_prot': self._get_protection_flags(cmd[1].initprot),
                        'sections': [
                            {
                                'name': sect.sectname.decode('utf-8').strip('\x00'),
                                'address': sect.addr,
                                'size': sect.size,
                                'flags': self._get_section_flags(sect.flags)
                            }
                            for sect in segment
                        ]
                    })
                except Exception as e:
                    print(f"Ошибка при обработке сегмента: {str(e)}")
                    continue
        return segments

    def _get_protection_flags(self, prot):
        """Получение флагов защиты"""
        flags = []
        if prot & VM_PROT_READ:
            flags.append('r')
        if prot & VM_PROT_WRITE:
            flags.append('w')
        if prot & VM_PROT_EXECUTE:
            flags.append('x')
        return ''.join(flags) if flags else '---'

    def _get_section_flags(self, flags):
        """Получение флагов секции"""
        result = []
        if flags & S_ATTR_PURE_INSTRUCTIONS:
            result.append('PURE_INSTRUCTIONS')
        if flags & S_ATTR_NO_TOC:
            result.append('NO_TOC')
        if flags & S_ATTR_STRIP_STATIC_SYMS:
            result.append('STRIP_STATIC_SYMS')
        if flags & S_ATTR_NO_DEAD_STRIP:
            result.append('NO_DEAD_STRIP')
        if flags & S_ATTR_LIVE_SUPPORT:
            result.append('LIVE_SUPPORT')
        if flags & S_ATTR_SELF_MODIFYING_CODE:
            result.append('SELF_MODIFYING_CODE')
        if flags & S_ATTR_DEBUG:
            result.append('DEBUG')
        if flags & S_ATTR_SOME_INSTRUCTIONS:
            result.append('SOME_INSTRUCTIONS')
        if flags & S_ATTR_EXT_RELOC:
            result.append('EXT_RELOC')
        if flags & S_ATTR_LOC_RELOC:
            result.append('LOC_RELOC')
        return result 