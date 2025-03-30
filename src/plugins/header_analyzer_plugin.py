from typing import Dict, Any, List
from core.plugin_base import MachOPlugin
from core.header_analyzer import HeaderAnalyzer
from core.constants import FLAG_DESCRIPTIONS, VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE, CPU_TYPE_X86, CPU_TYPE_X86_64, CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64
from macholib.mach_o import (
    LC_SEGMENT, LC_SEGMENT_64, MH_MAGIC_64, MH_CIGAM_64,
    S_ATTR_PURE_INSTRUCTIONS, S_ATTR_NO_TOC, S_ATTR_STRIP_STATIC_SYMS,
    S_ATTR_NO_DEAD_STRIP, S_ATTR_LIVE_SUPPORT, S_ATTR_SELF_MODIFYING_CODE,
    S_ATTR_DEBUG, S_ATTR_SOME_INSTRUCTIONS, S_ATTR_EXT_RELOC,
    S_ATTR_LOC_RELOC
)
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class HeaderAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа заголовков Mach-O файла"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.header_analyzer = HeaderAnalyzer(self.macho)
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует заголовок Mach-O файла"""
        results = {}
        
        for header in self.macho.headers:
            file_size = os.path.getsize(self.file_path)
            
            # Основная информация
            header_info = {
                "basic_info": {
                    "magic": f"{hex(header.header.magic)} ({self._get_magic_constant(header.header.magic)})",
                    "bitness": "64-bit" if header.header.magic in (0xFEEDFACF, 0xFEEDFACE) else "32-bit",
                    "cpu_type": self._get_cpu_type(header.header.cputype),
                    "cpu_subtype": self._get_cpu_subtype(header.header.cputype, header.header.cpusubtype),
                    "file_type": self._get_file_type(header.header.filetype),
                    "ncmds": header.header.ncmds,
                    "sizeofcmds": header.header.sizeofcmds,
                    "size": f"{file_size / 1024:.2f} Kb ({file_size} bytes)",
                    "modification_date": self._get_modification_date(0)
                },
                "segments": [],
                "sections": {},
                "versions": self._get_versions(header),
                "flags": self._get_flags(header)
            }
            
            # Анализируем сегменты
            for cmd in header.commands:
                if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    segment = cmd[1]
                    segname = segment.segname.decode('utf-8').strip('\x00')
                    
                    # Получаем значения сегмента
                    vmaddr = hex(segment.vmaddr) if hasattr(segment, 'vmaddr') else "0x0"
                    vmsize = hex(segment.vmsize) if hasattr(segment, 'vmsize') else "0x0"
                    fileoff = hex(segment.fileoff) if hasattr(segment, 'fileoff') else "0x0"
                    filesize = hex(segment.filesize) if hasattr(segment, 'filesize') else "0x0"
                    maxprot = self._get_protection_string(segment.maxprot) if hasattr(segment, 'maxprot') else "---"
                    initprot = self._get_protection_string(segment.initprot) if hasattr(segment, 'initprot') else "---"
                    nsects = segment.nsects if hasattr(segment, 'nsects') else 0
                    
                    header_info["segments"].append({
                        "name": segname,
                        "vmaddr": vmaddr,
                        "vmsize": vmsize,
                        "fileoff": fileoff,
                        "filesize": filesize,
                        "maxprot": maxprot,
                        "initprot": initprot,
                        "nsects": nsects
                    })
                    
                    # Собираем информацию о секциях
                    if hasattr(segment, 'nsects') and segment.nsects > 0:
                        sections_info = []
                        for section in cmd[2]:
                            try:
                                sectname = section.sectname.decode('utf-8').strip('\x00')
                                addr = hex(section.addr)
                                size = section.size
                                flags = self._get_section_flags(section.flags)
                                
                                sections_info.append({
                                    "name": sectname,
                                    "address": addr,
                                    "size": size,
                                    "flags": flags
                                })
                            except Exception as e:
                                print(f"Error reading section {sectname}: {str(e)}")
                                continue
                        
                        if sections_info:
                            header_info["sections"][segname] = sections_info
            
            results[f"header_{header.header.cputype}_{header.header.cpusubtype}"] = header_info
            
        return results
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> None:
        """Генерирует рекомендации на основе анализа"""
        recommendations = []
        
        # Проверяем флаги безопасности
        flags = results["details"]["flags"]
        if "MH_PIE" not in flags:
            recommendations.append("Рекомендуется включить PIE (Position Independent Executable)")
        if "MH_NO_HEAP_EXECUTION" not in flags:
            recommendations.append("Рекомендуется включить NO_HEAP_EXECUTION для предотвращения выполнения кода в куче")
            
        # Проверяем права доступа сегментов
        for segment in results["details"]["segments"]:
            if segment["name"] == "__TEXT" and "X" in segment["maxprot"]:
                recommendations.append("Сегмент __TEXT не должен иметь права на выполнение")
            if segment["name"] == "__DATA" and "X" in segment["maxprot"]:
                recommendations.append("Сегмент __DATA не должен иметь права на выполнение")
                
        results["recommendations"] = recommendations
    
    def _print_header_info(self, header_info: Dict[str, Any]) -> None:
        """Выводит информацию о заголовке файла"""
        try:
            # Основная информация
            basic_info = header_info["basic_info"]
            console.print("\n[bold magenta]Основная информация[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Magic", str(basic_info["magic"])],
                ["Битность", str(basic_info["bitness"])],
                ["CPU Type", str(basic_info["cpu_type"])],
                ["CPU Subtype", str(basic_info["cpu_subtype"])],
                ["Тип файла", str(basic_info["file_type"])],
                ["Количество команд", str(basic_info["ncmds"])],
                ["Размер команд", str(basic_info["sizeofcmds"])],
                ["Размер файла", str(basic_info["size"])],
                ["Дата модификации", str(basic_info["modification_date"])]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)

            # Версии и идентификаторы
            versions = header_info["versions"]
            if versions:
                console.print("\n[bold cyan]Версии и идентификаторы[/bold cyan]")
                version_table = Table(show_header=True, header_style="bold cyan")
                version_table.add_column("Параметр", style="cyan")
                version_table.add_column("Значение", style="yellow")
                
                for key, value in versions.items():
                    version_table.add_row(
                        key.replace("_", " ").title(),
                        str(value)
                    )
                console.print(version_table)

            # Флаги
            flags = header_info["flags"]
            if flags:
                console.print("\n[bold yellow]Флаги[/bold yellow]")
                flag_table = Table(show_header=True, header_style="bold yellow")
                flag_table.add_column("Флаг", style="cyan")
                flag_table.add_column("Описание", style="yellow")
                
                for flag, description in flags.items():
                    flag_table.add_row(flag, description)
                console.print(flag_table)

            # Сегменты
            if header_info["segments"]:
                console.print("\n[bold cyan]Сегменты[/bold cyan]")
                segment_table = Table(show_header=True, header_style="bold cyan")
                segment_table.add_column("Имя", style="cyan")
                segment_table.add_column("VMAddr", style="yellow")
                segment_table.add_column("VMSize", style="yellow")
                segment_table.add_column("FileOff", style="yellow")
                segment_table.add_column("FileSize", style="yellow")
                segment_table.add_column("Защита", style="yellow")
                segment_table.add_column("NSects", style="yellow")
                
                for segment in header_info["segments"]:
                    segment_table.add_row(
                        segment["name"],
                        segment["vmaddr"],
                        segment["vmsize"],
                        segment["fileoff"],
                        segment["filesize"],
                        f"max={segment['maxprot']}, init={segment['initprot']}",
                        str(segment["nsects"])
                    )
                console.print(segment_table)

            # Секции
            if header_info["sections"]:
                for segname, sections in header_info["sections"].items():
                    if sections:
                        console.print(f"\n[bold yellow]Секции в {segname}[/bold yellow]")
                        section_table = Table(show_header=True, header_style="bold yellow")
                        section_table.add_column("Имя", style="cyan")
                        section_table.add_column("Адрес", style="yellow")
                        section_table.add_column("Размер", style="yellow")
                        section_table.add_column("Флаги", style="yellow")
                        
                        for section in sections:
                            section_table.add_row(
                                section["name"],
                                section["address"],
                                str(section["size"]),
                                section["flags"]
                            )
                        console.print(section_table)
                
        except Exception as e:
            console.print(f"[red]Ошибка при выводе информации о заголовке: {str(e)}[/red]")

    def _print_file_info(self, header_info: Dict[str, Any]) -> None:
        """Алиас для _print_header_info для обратной совместимости"""
        self._print_header_info(header_info)
    
    def _get_basic_info(self, header) -> Dict[str, Any]:
        """Получает базовую информацию о заголовке"""
        file_info = self.header_analyzer.get_file_info()
        return {
            "magic": self.header_analyzer._get_magic(header),
            "bitness": "64-bit" if header.header.magic in (MH_MAGIC_64, MH_CIGAM_64) else "32-bit",
            "cpu_type": self.header_analyzer._get_cpu_type(header.header.cputype),
            "cpu_subtype": str(header.header.cpusubtype),
            "file_type": self.header_analyzer._get_file_type(header.header.filetype),
            "ncmds": str(header.header.ncmds),
            "sizeofcmds": f"{header.header.sizeofcmds} байт",
            "size": file_info['size_bytes'],
            "modification_date": file_info['modification_date']
        }
    
    def _get_versions(self, header) -> Dict[str, str]:
        """Получает информацию о версиях"""
        load_cmd_data = self.header_analyzer._get_load_command_data(header)
        versions = {}
        
        if load_cmd_data.get('uuid'):
            versions['uuid'] = load_cmd_data['uuid']
        if load_cmd_data.get('min_version'):
            versions['min_os_version'] = load_cmd_data['min_version']
        if load_cmd_data.get('sdk_version'):
            versions['sdk_version'] = load_cmd_data['sdk_version']
        if load_cmd_data.get('source_version'):
            versions['source_version'] = load_cmd_data['source_version']
        if load_cmd_data.get('build_version'):
            versions['build_version'] = load_cmd_data['build_version']
            
        return versions
    
    def _get_flags(self, header) -> Dict[str, str]:
        """Получает информацию о флагах"""
        flags = {}
        for flag in self.header_analyzer._get_flags(header.header.flags):
            flags[flag] = FLAG_DESCRIPTIONS.get(flag, "Неизвестный флаг")
        return flags

    def get_segments(self, header) -> List[Dict[str, Any]]:
        """Получение информации о сегментах"""
        segments = []
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                try:
                    segment = cmd[2]  # Это сегмент
                    segname = cmd[1].segname.decode('utf-8').strip('\x00') if cmd[1].segname else "Unknown"
                    segments.append({
                        'name': segname,
                        'vm_address': cmd[1].vmaddr,
                        'vm_size': cmd[1].vmsize,
                        'file_offset': cmd[1].fileoff,
                        'file_size': cmd[1].filesize,
                        'max_prot': self._get_protection_flags(cmd[1].maxprot),
                        'init_prot': self._get_protection_flags(cmd[1].initprot),
                        'sections': [
                            {
                                'name': sect.sectname.decode('utf-8').strip('\x00') if sect.sectname else "Unknown",
                                'address': sect.addr,
                                'size': sect.size,
                                'flags': self._get_section_flags(sect.flags)
                            }
                            for sect in segment
                        ]
                    })
                except Exception as e:
                    self.print_error(f"Ошибка при обработке сегмента: {str(e)}")
                    continue
        return segments

    def _get_protection_flags(self, prot) -> str:
        """Получение флагов защиты"""
        flags = []
        if prot & VM_PROT_READ:
            flags.append('r')
        if prot & VM_PROT_WRITE:
            flags.append('w')
        if prot & VM_PROT_EXECUTE:
            flags.append('x')
        return ''.join(flags) if flags else '---'

    def _get_section_flags(self, flags: int) -> str:
        """Преобразует флаги секции в читаемый формат"""
        flag_list = []
        if flags & S_ATTR_PURE_INSTRUCTIONS:
            flag_list.append("PURE_INSTRUCTIONS")
        if flags & S_ATTR_NO_TOC:
            flag_list.append("NO_TOC")
        if flags & S_ATTR_STRIP_STATIC_SYMS:
            flag_list.append("STRIP_STATIC_SYMS")
        if flags & S_ATTR_NO_DEAD_STRIP:
            flag_list.append("NO_DEAD_STRIP")
        if flags & S_ATTR_LIVE_SUPPORT:
            flag_list.append("LIVE_SUPPORT")
        if flags & S_ATTR_SELF_MODIFYING_CODE:
            flag_list.append("SELF_MODIFYING_CODE")
        if flags & S_ATTR_DEBUG:
            flag_list.append("DEBUG")
        if flags & S_ATTR_SOME_INSTRUCTIONS:
            flag_list.append("SOME_INSTRUCTIONS")
        if flags & S_ATTR_EXT_RELOC:
            flag_list.append("EXT_RELOC")
        if flags & S_ATTR_LOC_RELOC:
            flag_list.append("LOC_RELOC")
        
        return ", ".join(flag_list) if flag_list else "-"
    
    def _get_cpu_type(self, cputype: int) -> str:
        """Получает тип CPU"""
        cpu_types = {
            CPU_TYPE_X86: "x86",
            CPU_TYPE_X86_64: "x86_64",
            CPU_TYPE_ARM: "ARM",
            CPU_TYPE_ARM64: "ARM64",
            CPU_TYPE_ARM64_32: "ARM64_32",
            CPU_TYPE_POWERPC: "PowerPC",
            CPU_TYPE_POWERPC64: "PowerPC64"
        }
        return cpu_types.get(cputype, "Unknown")

    def _get_cpu_subtype(self, cputype: int, cpusubtype: int) -> str:
        """Получает подтип CPU"""
        if cputype == CPU_TYPE_X86:
            return "All"
        elif cputype == CPU_TYPE_X86_64:
            return "All"
        elif cputype == CPU_TYPE_ARM:
            return "All"
        elif cputype == CPU_TYPE_ARM64:
            return "All"
        elif cputype == CPU_TYPE_ARM64_32:
            return "All"
        elif cputype == CPU_TYPE_POWERPC:
            return "All"
        elif cputype == CPU_TYPE_POWERPC64:
            return "All"
        return "Unknown"

    def _get_file_type(self, filetype: int) -> str:
        """Получает тип файла"""
        file_types = {
            0x1: "Object",
            0x2: "Executable",
            0x3: "Fixed VM shared library",
            0x4: "Core",
            0x5: "Preloaded executable",
            0x6: "Dynamically linked shared library",
            0x7: "Dynamic linker",
            0x8: "Bundle",
            0x9: "Dynamically linked shared library stub",
            0xA: "DSYM companion",
            0xB: "KEXT bundle"
        }
        return file_types.get(filetype, "Unknown")

    def _get_modification_date(self, mtime: int) -> str:
        """Получает дату модификации"""
        try:
            # Получаем время модификации файла напрямую из файловой системы
            return datetime.fromtimestamp(os.path.getmtime(self.file_path)).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Unknown"
    
    def _get_magic_constant(self, magic: int) -> str:
        """Получает название константы для magic"""
        magic_constants = {
            0xFEEDFACF: "MH_MAGIC_64",
            0xFEEDFACE: "MH_MAGIC",
            0xCEFAEDFE: "MH_CIGAM",
            0xCFAEDFEF: "MH_CIGAM_64"
        }
        return magic_constants.get(magic, "Unknown")
    
    def _get_protection_string(self, prot: int) -> str:
        """Преобразует числовое значение защиты в читаемый формат (R--, -WX, R-X и т.д.)"""
        result = ""
        result += "R" if prot & VM_PROT_READ else "-"
        result += "W" if prot & VM_PROT_WRITE else "-"
        result += "X" if prot & VM_PROT_EXECUTE else "-"
        return result
    
    @staticmethod
    def get_name() -> str:
        return "header_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует заголовки Mach-O файла, включая базовую информацию, версии и флаги"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 