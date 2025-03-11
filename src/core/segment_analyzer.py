from dataclasses import dataclass
from typing import List, Optional
from macholib.MachO import MachO
from macholib.mach_o import *

@dataclass
class Section:
    """Информация о секции"""
    name: str
    segment_name: str
    address: int
    size: int
    offset: int
    align: int
    flags: List[str]
    type: str

@dataclass
class Segment:
    """Информация о сегменте"""
    name: str
    vm_address: int
    vm_size: int
    file_offset: int
    file_size: int
    max_prot: str
    init_prot: str
    flags: List[str]
    sections: List[Section]

class SegmentAnalyzer:
    """Анализатор сегментов и секций Mach-O файлов"""
    
    def __init__(self, macho: MachO):
        self.macho = macho

    def _get_prot_flags(self, prot: int) -> str:
        """Получить список флагов защиты"""
        r = "R" if prot & 0b001 else "-"
        w = "W" if prot & 0b010 else "-"
        x = "X" if prot & 0b100 else "-"
        return f"{r}{w}{x}"

    def _get_section_type(self, flags: int) -> str:
        """Получить тип секции"""
        section_types = {
            S_REGULAR: "REGULAR",
            S_ZEROFILL: "ZEROFILL",
            S_CSTRING_LITERALS: "CSTRING_LITERALS",
            S_4BYTE_LITERALS: "4BYTE_LITERALS",
            S_8BYTE_LITERALS: "8BYTE_LITERALS",
            S_LITERAL_POINTERS: "LITERAL_POINTERS",
            S_NON_LAZY_SYMBOL_POINTERS: "NON_LAZY_SYMBOL_POINTERS",
            S_LAZY_SYMBOL_POINTERS: "LAZY_SYMBOL_POINTERS",
            S_SYMBOL_STUBS: "SYMBOL_STUBS",
            S_MOD_INIT_FUNC_POINTERS: "MOD_INIT_FUNC_POINTERS",
            S_MOD_TERM_FUNC_POINTERS: "MOD_TERM_FUNC_POINTERS",
            S_COALESCED: "COALESCED",
            S_GB_ZEROFILL: "GB_ZEROFILL",
            S_INTERPOSING: "INTERPOSING",
            S_16BYTE_LITERALS: "16BYTE_LITERALS",
            S_DTRACE_DOF: "DTRACE_DOF",
            S_LAZY_DYLIB_SYMBOL_POINTERS: "LAZY_DYLIB_SYMBOL_POINTERS",
            S_THREAD_LOCAL_REGULAR: "THREAD_LOCAL_REGULAR",
            S_THREAD_LOCAL_ZEROFILL: "THREAD_LOCAL_ZEROFILL",
            S_THREAD_LOCAL_VARIABLES: "THREAD_LOCAL_VARIABLES",
            S_THREAD_LOCAL_VARIABLE_POINTERS: "THREAD_LOCAL_VARIABLE_POINTERS",
            S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: "THREAD_LOCAL_INIT_FUNCTION_POINTERS"
        }
        type_mask = flags & SECTION_TYPE
        return section_types.get(type_mask, f"Unknown ({type_mask})")

    def _get_section_flags(self, flags: int) -> List[str]:
        """Получить список флагов секции"""
        section_flags = []
        if flags & S_ATTR_PURE_INSTRUCTIONS:
            section_flags.append("PURE_INSTRUCTIONS")
        if flags & S_ATTR_NO_TOC:
            section_flags.append("NO_TOC")
        if flags & S_ATTR_STRIP_STATIC_SYMS:
            section_flags.append("STRIP_STATIC_SYMS")
        if flags & S_ATTR_NO_DEAD_STRIP:
            section_flags.append("NO_DEAD_STRIP")
        if flags & S_ATTR_LIVE_SUPPORT:
            section_flags.append("LIVE_SUPPORT")
        if flags & S_ATTR_SELF_MODIFYING_CODE:
            section_flags.append("SELF_MODIFYING_CODE")
        if flags & S_ATTR_DEBUG:
            section_flags.append("DEBUG")
        if flags & S_ATTR_SOME_INSTRUCTIONS:
            section_flags.append("SOME_INSTRUCTIONS")
        if flags & S_ATTR_EXT_RELOC:
            section_flags.append("EXT_RELOC")
        if flags & S_ATTR_LOC_RELOC:
            section_flags.append("LOC_RELOC")
        return section_flags

    def _get_segment_flags(self, flags: int) -> List[str]:
        """Получить список флагов сегмента"""
        segment_flags = []
        if flags & SG_HIGHVM:
            segment_flags.append("HIGHVM")
        if flags & SG_FVMLIB:
            segment_flags.append("FVMLIB")
        if flags & SG_NORELOC:
            segment_flags.append("NORELOC")
        if flags & SG_PROTECTED_VERSION_1:
            segment_flags.append("PROTECTED_VERSION_1")
        return segment_flags

    def analyze_segments(self, header) -> List[Segment]:
        """Анализировать сегменты и секции в заголовке"""
        segments = []
        
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                seg = cmd[1]
                sections = []
                
                # Анализ секций в сегменте
                for section in cmd[2]:
                    sect = Section(
                        name=section.sectname.decode('utf-8').rstrip('\x00'),
                        segment_name=section.segname.decode('utf-8').rstrip('\x00'),
                        address=section.addr,
                        size=section.size,
                        offset=section.offset,
                        align=section.align,
                        flags=self._get_section_flags(section.flags),
                        type=self._get_section_type(section.flags)
                    )
                    sections.append(sect)
                
                # Создаем объект сегмента
                segment = Segment(
                    name=seg.segname.decode('utf-8').rstrip('\x00'),
                    vm_address=seg.vmaddr,
                    vm_size=seg.vmsize,
                    file_offset=seg.fileoff,
                    file_size=seg.filesize,
                    max_prot=self._get_prot_flags(seg.maxprot),
                    init_prot=self._get_prot_flags(seg.initprot),
                    flags=self._get_segment_flags(seg.flags),
                    sections=sections
                )
                segments.append(segment)
        
        return segments 