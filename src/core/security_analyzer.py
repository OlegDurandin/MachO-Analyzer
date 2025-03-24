from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any
from macholib.MachO import MachO, MachOHeader
from macholib.mach_o import *
import struct
from pathlib import Path
from .header_analyzer import HeaderAnalyzer
from .constants import VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE, CPU_TYPE_ARM64
from .sign_analyzer import SignAnalyzer, SignStatus, SignType
from .symbol_analyzer import SymbolAnalyzer, SymbolType
from .debug_analyzer import DebugAnalyzer


LC_SEGMENT_SPLIT_INFO = 0x1E


class SeverityLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityIssue:
    """Информация о механизме защиты или проблеме безопасности"""
    description: str
    severity: SeverityLevel
    details: str
    is_problem: bool  # True для проблем, False для информации о защите
    recommendation: Optional[str] = None

class SecurityAnalyzer:
    """Анализатор механизмов защиты в Mach-O файлах"""
    
    def __init__(self, macho: MachO, file_path: str):
        self.macho = macho
        self.file_path = file_path
        self.vulnerable_functions = {
            'gets': 'Использование небезопасной функции gets()',
            'strcpy': 'Использование небезопасной функции strcpy()',
            'strcat': 'Использование небезопасной функции strcat()',
            'sprintf': 'Использование небезопасной функции sprintf()',
            'vsprintf': 'Использование небезопасной функции vsprintf()'
        }

    def _check_ASLR_mechanism(self, header) -> List[SecurityIssue]:
        # ASLR (Position Independent Executable)
        issues = []
        if header.header.flags & MH_PIE:
            issues.append(SecurityIssue(
                description="ASLR (Address Space Layout Randomization)",
                severity=SeverityLevel.INFO,
                details="Включена рандомизация адресного пространства",
                is_problem=False,
                recommendation=None
            ))
        else:
            issues.append(SecurityIssue(
                description="Отсутствует ASLR",
                severity=SeverityLevel.WARNING,
                details="Бинарный файл скомпилирован без поддержки ASLR",
                is_problem=True,
                recommendation="Рекомендуется перекомпилировать с флагом -fPIE"
            ))
        return issues
    

 

    def _check_relro(self, header) -> List[SecurityIssue]:
        """Проверка механизма защиты RELRO (RELocation Read-Only)"""
        issues = []
        has_data_const = False
        has_got_protection = False

        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                seg = cmd[1]
                segname = seg.segname.decode('utf-8').rstrip('\x00')
                
                # Проверяем наличие __DATA_CONST
                if segname == '__DATA_CONST':
                    has_data_const = True
                    
                    # Проверяем права доступа - должен быть только для чтения после инициализации
                    if (seg.initprot & VM_PROT_WRITE) and not (seg.maxprot & VM_PROT_WRITE):
                        has_got_protection = True
                    
                    # Проверяем секции внутри __DATA_CONST
                    for sect in cmd[2]:
                        sect_name = sect.sectname.decode('utf-8').rstrip('\x00')
                        if sect_name in ('__got', '__la_symbol_ptr', '__nl_symbol_ptr'):
                            # Эти секции должны быть в __DATA_CONST
                            has_got_protection = True
                            break

        if has_data_const and has_got_protection:
            issues.append(SecurityIssue(
                description="RELRO (RELocation Read-Only)",
                severity=SeverityLevel.INFO,
                details="Включена полная защита GOT (Global Offset Table)",
                is_problem=False,
                recommendation=None
            ))
        elif has_data_const:
            issues.append(SecurityIssue(
                description="Частичный RELRO",
                severity=SeverityLevel.INFO,
                details="Включена базовая защита GOT через __DATA_CONST",
                is_problem=False,
                recommendation="Для лучшей защиты рекомендуется включить полный RELRO"
            ))
        else:
            issues.append(SecurityIssue(
                description="Отсутствует RELRO",
                severity=SeverityLevel.WARNING,
                details="Отсутствует защита GOT от перезаписи",
                is_problem=True,
                recommendation="Рекомендуется включить защиту RELRO при компиляции"
            ))
        
        return issues
        
    
    def _check_nx(self, header) -> List[SecurityIssue]:
        issues = []
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                seg = cmd[1]
                segname = seg.segname.decode('utf-8').rstrip('\x00')
                permissions = seg.maxprot
                if segname == '__DATA':
                    if permissions & VM_PROT_EXECUTE:
                        issues.append(SecurityIssue(
                            description=f"Исполняемый сегмент {segname}",
                            severity=SeverityLevel.WARNING,
                            details=f"Разрешено выполнение кода в сегменте {segname}",
                            is_problem=True,
                            recommendation=f"Сегмент {segname} не должен быть исполняемым"
                        ))
                    else:
                        issues.append(SecurityIssue(
                            description=f"Защита сегмента {segname}",
                            severity=SeverityLevel.INFO,
                            details=f"Сегмент {segname} защищен от выполнения кода",
                            is_problem=False,
                            recommendation=None
                        ))  
        return issues   



    def _check_base_security(self, header) -> List[SecurityIssue]:
        """Проверка базовых механизмов защиты"""
        issues = []    

        # Stack Protection
        if header.header.flags & MH_ALLOW_STACK_EXECUTION:
            issues.append(SecurityIssue(
                description="Стек исполняемый",
                severity=SeverityLevel.WARNING,
                details="Разрешено выполнение кода в стеке",
                is_problem=True,
                recommendation="Рекомендуется отключить исполняемый стек"
            ))
        else:
            issues.append(SecurityIssue(
                description="Защита стека от выполнения",
                severity=SeverityLevel.INFO,
                details="Стек не является исполняемым",
                is_problem=False,
                recommendation=None
            ))
        return issues
    

    def _check_fortify_source(self, header) -> List[SecurityIssue]:
        """Проверка механизма защиты FORTIFY_SOURCE"""
        issues = []
        fortify_functions = False
        bounds_checking = False
        
        # Список защищенных функций, которые добавляются при FORTIFY_SOURCE
        protected_functions = [
            '__strcpy_chk',
            '__memcpy_chk',
            '__memmove_chk',
            '__memset_chk',
            '__strncpy_chk',
            '__strncat_chk',
            '__sprintf_chk',
            '__snprintf_chk',
            '__vsprintf_chk',
            '__vsnprintf_chk',
            '__strcat_chk'
        ]
        
        for cmd in header.commands:
            if cmd[0].cmd == LC_SYMTAB:
                symtab = cmd[1]
                stroff = symtab.stroff
                strsize = symtab.strsize
                
                try:
                    with open(self.file_path, 'rb') as f:
                        f.seek(stroff)
                        string_table = f.read(strsize)
                        
                        if string_table:
                            # Декодируем таблицу строк и ищем защищенные функции
                            strings = string_table.decode('utf-8', errors='ignore')
                            
                            # Проверяем наличие защищенных функций
                            for func in protected_functions:
                                if func in strings:
                                    fortify_functions = True
                                    break
                            
                            # Проверяем наличие функций проверки границ
                            if '__chk_fail' in strings or '__stack_chk_guard' in strings:
                                bounds_checking = True
                except (IOError, OSError) as e:
                    issues.append(SecurityIssue(
                        description="Ошибка проверки FORTIFY_SOURCE",
                        severity=SeverityLevel.WARNING,
                        details=f"Не удалось проверить наличие FORTIFY_SOURCE: {str(e)}",
                        is_problem=True,
                        recommendation="Проверьте доступ к файлу"
                    ))
                    return issues

        if fortify_functions and bounds_checking:
            issues.append(SecurityIssue(
                description="FORTIFY_SOURCE",
                severity=SeverityLevel.INFO,
                details="Включена полная защита от переполнения буфера (FORTIFY_SOURCE=2)",
                is_problem=False,
                recommendation=None
            ))
        elif fortify_functions or bounds_checking:
            issues.append(SecurityIssue(
                description="Частичный FORTIFY_SOURCE",
                severity=SeverityLevel.INFO,
                details="Обнаружена базовая защита от переполнения буфера",
                is_problem=False,
                recommendation="Рекомендуется включить полный FORTIFY_SOURCE=2 при компиляции"
            ))
        else:
            issues.append(SecurityIssue(
                description="Отсутствует FORTIFY_SOURCE",
                severity=SeverityLevel.WARNING,
                details="Отсутствует защита от переполнения буфера",
                is_problem=True,
                recommendation="Рекомендуется включить -D_FORTIFY_SOURCE=2 при компиляции"
            ))
        
        return issues
    
    def __check_stack_canary(self, header) -> List[SecurityIssue]:
        issues = []
        # Stack Canary
        has_stack_canary = False
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                seg = cmd[1]
                seg_name = seg.segname.decode('utf-8').rstrip('\x00')
                if seg_name == '__TEXT':
                    for sect in cmd[2]:
                        sect_name = sect.sectname.decode('utf-8').rstrip('\x00')
                        # Ищем секцию __stack_chk_guard или символ ___stack_chk_guard
                        if 'stack_chk' in sect_name:
                            has_stack_canary = True
                            break

            elif cmd[0].cmd == LC_SYMTAB:
                # Проверяем наличие символов stack canary
                symtab = cmd[1]
                
                
                symoff = symtab.symoff
                nsyms = symtab.nsyms
                stroff = symtab.stroff
                strsize = symtab.strsize
                
                # Workaround to read string table
                f = open(self.file_path, 'rb')
                f.seek(stroff)
                string_table = f.read(strsize)

                if string_table:
                    function_names = string_table.decode('utf-8', errors='ignore').split('\x00')
                    if '___stack_chk_guard' in function_names or '___stack_chk_fail' in function_names:
                        has_stack_canary = True
                        f.close()
                        break
                f.close()
        
        if has_stack_canary:
            issues.append(SecurityIssue(
                description="Stack Canary",
                severity=SeverityLevel.INFO,
                details="Включена защита стека от переполнения (stack canary)",
                is_problem=False,
                recommendation=None
            ))
        else:
            issues.append(SecurityIssue(
                description="Отсутствует Stack Canary",
                severity=SeverityLevel.WARNING,
                details="Отсутствует защита стека от переполнения",
                is_problem=True,
                recommendation="Рекомендуется включить -fstack-protector-strong при компиляции"
            ))

        return issues

    def _check_canaries(self, header) -> List[SecurityIssue]:
        """Проверка наличия и реализации канареек"""
        issues = []
        
        # Проверяем наличие канареек в секции __DATA
        for cmd in header.commands:
            if cmd[0].cmd == LC_SEGMENT_64:
                segment = cmd[1]
                sections = cmd[2]
                if segment.segname.decode('utf-8').rstrip('\x00') == '__DATA':
                    for section in sections:
                        if section.sectname.decode('utf-8').rstrip('\x00') == '__bss':
                            # Ищем канарейки в BSS секции
                            try:
                                with open(self.file_path, 'rb') as f:
                                    f.seek(section.offset)
                                    data = f.read(section.size)
                                    if data:
                                        # Ищем характерные паттерны канареек
                                        patterns = [
                                            b'\x00\x00\x00\x00\x00\x00\x00\x00',  # 64-bit zero canary
                                            b'\x00\x00\x00\x00',                  # 32-bit zero canary
                                            b'\xff\xff\xff\xff\xff\xff\xff\xff',  # 64-bit terminator canary
                                            b'\xff\xff\xff\xff'                   # 32-bit terminator canary
                                        ]
                                        
                                        for pattern in patterns:
                                            if pattern in data:
                                                issues.append(SecurityIssue(
                                                    description="Обнаружена канарейка",
                                                    severity=SeverityLevel.INFO,
                                                    details=f"Найдена канарейка типа {pattern.hex()} в секции __bss",
                                                    is_problem=False
                                                ))
                                                break
                            except (IOError, OSError) as e:
                                issues.append(SecurityIssue(
                                    description="Ошибка при анализе канареек",
                                    severity=SeverityLevel.WARNING,
                                    details=f"Не удалось прочитать секцию __bss: {str(e)}",
                                    is_problem=True
                                ))

        # Проверяем наличие функций, связанных с канарейками
        canary_functions = [
            '__stack_chk_fail',
            '__stack_chk_guard',
            '__stack_chk_guard_setup'
        ]
        
        for function in canary_functions:
            if self._find_symbol(function):
                issues.append(SecurityIssue(
                    description="Обнаружена функция защиты канареек",
                    severity=SeverityLevel.INFO,
                    details=f"Найдена функция {function}",
                    is_problem=False
                ))

        if not issues:
            issues.append(SecurityIssue(
                description="Канарейки не обнаружены",
                severity=SeverityLevel.WARNING,
                details="Не найдено признаков использования канареек",
                is_problem=True,
                recommendation="Рекомендуется добавить защиту канареек для предотвращения переполнения стека"
            ))

        return issues

    def _find_symbol(self, symbol_name: str) -> bool:
        """Поиск символа в бинарном файле"""
        for header in self.macho.headers:
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
                    
                    # Читаем таблицу строк
                    with open(self.file_path, 'rb') as f:
                        f.seek(strtab.stroff)
                        string_table = f.read(strtab.strsize)
                        
                        if symbol_name.encode() in string_table:
                            return True
        
        return False

    def _check_code_signing(self) -> List[SecurityIssue]:
        """Проверка механизмов подписи кода"""
        issues = []
        
        # Используем SignAnalyzer для анализа подписи
        sign_analyzer = SignAnalyzer(self.file_path)
        sign_info = sign_analyzer.analyze()
        
        if sign_info.status == SignStatus.NOT_SIGNED:
            issues.append(SecurityIssue(
                description="Отсутствует подпись кода",
                severity=SeverityLevel.WARNING,
                details="Файл не подписан",
                is_problem=True,
                recommendation="Рекомендуется подписать файл для улучшения безопасности"
            ))
        elif sign_info.status == SignStatus.INVALID:
            issues.append(SecurityIssue(
                description="Недействительная подпись кода",
                severity=SeverityLevel.CRITICAL,
                details=sign_info.details,
                is_problem=True,
                recommendation="Проверьте целостность подписи и сертификаты"
            ))
        else:
            # Подпись валидна
            details = f"Тип подписи: {sign_info.sign_type.value}"
            if sign_info.team_id:
                details += f"\nTeam ID: {sign_info.team_id}"
            if sign_info.timestamp:
                details += f"\nTimestamp: {sign_info.timestamp}"
                
            issues.append(SecurityIssue(
                description="Подпись кода",
                severity=SeverityLevel.INFO,
                details=details,
                is_problem=False,
                recommendation=None
            ))
            
            # Дополнительные проверки в зависимости от типа подписи
            if sign_info.sign_type == SignType.ADHOC:
                issues.append(SecurityIssue(
                    description="Самостоятельная подпись",
                    severity=SeverityLevel.WARNING,
                    details="Файл подписан самостоятельно (ad-hoc)",
                    is_problem=True,
                    recommendation="Рекомендуется использовать Developer ID или Apple подпись"
                ))

        return issues

    def _check_hardening(self, header) -> List[SecurityIssue]:
        """Проверка механизмов усиления защиты"""
        issues = []
        
        # Проверяем сегменты на права доступа
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                seg = cmd[1]
                seg_name = seg.segname.decode('utf-8').rstrip('\x00')
                
                # Проверяем __TEXT
                if seg_name == '__TEXT':
                    if seg.initprot & VM_PROT_WRITE:
                        issues.append(SecurityIssue(
                            description="Сегмент __TEXT доступен для записи",
                            severity=SeverityLevel.WARNING,
                            details="Сегмент кода не должен быть доступен для записи",
                            is_problem=True,
                            recommendation="Проверьте права доступа к сегменту __TEXT"
                        ))
                    else:
                        issues.append(SecurityIssue(
                            description="Защита сегмента __TEXT",
                            severity=SeverityLevel.INFO,
                            details="Сегмент кода защищен от записи",
                            is_problem=False,
                            recommendation=None
                        ))
                
                # Проверяем __DATA
                elif seg_name == '__DATA':
                    if seg.initprot & VM_PROT_EXECUTE:
                        issues.append(SecurityIssue(
                            description="Сегмент __DATA исполняемый",
                            severity=SeverityLevel.WARNING,
                            details="Сегмент данных не должен быть исполняемым",
                            is_problem=True,
                            recommendation="Проверьте права доступа к сегменту __DATA"
                        ))
                    else:
                        issues.append(SecurityIssue(
                            description="Защита сегмента __DATA",
                            severity=SeverityLevel.INFO,
                            details="Сегмент данных не является исполняемым",
                            is_problem=False,
                            recommendation=None
                        ))

        return issues
    
    def _check_encryption(self, header) -> List[SecurityIssue]:
        """Проверка механизмов шифрования"""
        issues = []
        
        for cmd in header.commands:
            if cmd[0].cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                if cmd[1].cryptid == 1:
                    issues.append(SecurityIssue(
                        description="Шифрование",
                        severity=SeverityLevel.INFO,
                        details="Файл зашифрован",
                        is_problem=False,
                        recommendation=None
                    ))
                else:
                    issues.append(SecurityIssue(
                        description="Отсутствует шифрование",
                        severity=SeverityLevel.INFO,
                        details="Файл содержит сегмент шифрования, но не зашифрован",
                        is_problem=True,
                        recommendation="Возможно, файл расшифрован или требует шифрования"
                    ))

        return issues

    def _check_symbols_and_imports(self) -> List[SecurityIssue]:
        """Проверка символов и импортов"""
        issues = []
        
        symbol_analyzer = SymbolAnalyzer(self.macho, self.file_path)
        symbols, libraries = symbol_analyzer.analyze()
        
        # Анализ слабых символов
        weak_symbols = [s for s in symbols if s.is_weak]
        if weak_symbols:
            issues.append(SecurityIssue(
                description="Слабые символы",
                severity=SeverityLevel.WARNING,
                details=f"Найдено {len(weak_symbols)} слабых символов. Слабые символы могут быть переопределены, что может привести к проблемам безопасности.",
                is_problem=True,
                recommendation="Проверьте использование слабых символов и рассмотрите возможность использования сильных символов для критических функций"
            ))
            
        # Анализ неопределенных символов
        undefined_symbols = [s for s in symbols if s.is_undefined]
        if undefined_symbols:
            issues.append(SecurityIssue(
                description="Неопределенные символы",
                severity=SeverityLevel.WARNING,
                details=f"Найдено {len(undefined_symbols)} неопределенных символов. Это может указывать на отсутствующие зависимости.",
                is_problem=True,
                recommendation="Проверьте все зависимости и убедитесь, что все необходимые библиотеки доступны"
            ))
            
        # Анализ динамических библиотек
        if libraries:
            # Группируем библиотеки по типам
            system_libs = []
            private_libs = []
            weak_libs = []
            reexported_libs = []
            
            for lib in libraries:
                if lib.is_weak:
                    weak_libs.append(lib)
                if lib.is_reexported:
                    reexported_libs.append(lib)
                if lib.is_private:
                    private_libs.append(lib)
                elif lib.is_system:
                    system_libs.append(lib)
            
            # Формируем детальный отчет
            details = []
            
            # Выводим статистику
            details.append(f"Статистика библиотек:")
            details.append(f"  Всего: {len(libraries)}")
            details.append(f"  Системных: {len(system_libs)}")
            details.append(f"  Приватных: {len(private_libs)}")
            details.append(f"  Слабых: {len(weak_libs)}")
            details.append(f"  Реэкспортируемых: {len(reexported_libs)}")
            details.append("")
            
            # Список подозрительных библиотек
            suspicious_libs = {
                # Криптография и безопасность
                'libcrypto': 'Криптографические операции',
                'libssl': 'TLS/SSL операции',
                'libprotobuf': 'Сериализация данных',
                'libsecurity': 'Системы безопасности',
                'libcommoncrypto': 'Криптографические операции',
                'libkeychain': 'Работа с ключами',
                'libtls': 'TLS/SSL операции',
                
                # Сетевая активность
                'libcurl': 'HTTP-запросы',
                'libresolv': 'DNS-запросы',
                'libsystem_dnssd': 'DNS-запросы',
                'libsystem_networkextension': 'Сетевые расширения',
                'libnetworkextension': 'Сетевые расширения',
                'libcfnetwork': 'Сетевые операции',
                'libsystem_networking': 'Сетевые операции',
                
                # Системные операции
                'libsystem_kernel': 'Системные вызовы',
                'libsystem_platform': 'Платформенные функции',
                'libsystem_info': 'Системная информация',
                'libsystem_trace': 'Отслеживание',
                'libsystem_notify': 'Системные уведомления',
                'libsystem_coreservices': 'Системные сервисы',
                'libsystem_configuration': 'Конфигурация системы',
                
                # Работа с данными
                'libsqlite3': 'Работа с базой данных',
                'libz': 'Сжатие данных',
                'libxml2': 'Парсинг XML',
                'libxslt': 'Преобразование XML',
                'libjson': 'Работа с JSON',
                'libarchive': 'Работа с архивами',
                'libcompression': 'Сжатие данных',
                
                # Асинхронные операции
                'libdispatch': 'Асинхронные операции',
                
                # Работа с процессами
                'libproc': 'Управление процессами',
                
                # Работа с памятью
                'libmalloc': 'Управление памятью',
                
                # Работа с файловой системой
                'libsystem_fs': 'Файловая система',
                
                # Приватные системные библиотеки
                'libsystem_private': 'Приватные системные функции',
                'libsecurity_interface_private': 'Приватный интерфейс безопасности',
                'libsystem_network_extension_interface_private': 'Приватный интерфейс сетевых расширений',
                'libsystem_extension_interface_private': 'Приватный интерфейс системных расширений',
                'libdispatch_private': 'Приватные асинхронные операции',
                'libproc_private': 'Приватное управление процессами',
                'libmalloc_private': 'Приватное управление памятью',
                'libsystem_fs_private': 'Приватная файловая система'
            }
            
            # Анализируем подозрительные библиотеки
            suspicious_found = []
            for lib in libraries:
                for susp_name, description in suspicious_libs.items():
                    if susp_name in lib.name.lower():
                        suspicious_found.append((lib.name, description))
            
            if suspicious_found:
                details.append("Подозрительные библиотеки:")
                for lib_name, description in suspicious_found:
                    details.append(f"  - {lib_name}")
                    details.append(f"    Причина: {description}")
                details.append("")
            
            # Выводим все библиотеки с их характеристиками (не более 50)
            details.append("Подробная информация о библиотеках:")
            for lib in libraries:
                flags = []
                if lib.is_weak:
                    flags.append("weak")
                if lib.is_reexported:
                    flags.append("reexport")
                if lib.is_private:
                    flags.append("private")
                if lib.is_system:
                    flags.append("system")
                
                # Определяем тип библиотеки
                lib_type = "Unknown"
                if lib.name.startswith('/usr/lib/swift/'):
                    lib_type = "Swift"
                elif lib.name.startswith('/System/Library/Frameworks/'):
                    lib_type = "Framework"
                elif lib.name.startswith('/usr/lib/'):
                    lib_type = "System"
                elif lib.name.startswith('@rpath/'):
                    lib_type = "Runtime"
                
                # Формируем строку с информацией
                info = []
                info.append(f"  - {lib.name}")
                info.append(f"    Тип: {lib_type}")
                if flags:
                    info.append(f"    Характеристики: ({', '.join(flags)})")
                if lib.path:
                    info.append(f"    Путь: {lib.path}")
                
                details.append("\n".join(info))
            
            # Проверяем безопасность
            security_concerns = []
            if private_libs:
                security_concerns.append("Использование приватных библиотек может быть небезопасным")
            if weak_libs:
                security_concerns.append("Слабые библиотеки могут быть переопределены")
            if not system_libs:
                security_concerns.append("Отсутствуют системные библиотеки, возможно используется нестандартный набор зависимостей")
                
            severity = SeverityLevel.WARNING if security_concerns else SeverityLevel.INFO
            is_problem = bool(security_concerns)
            
            issues.append(SecurityIssue(
                description="Динамические библиотеки",
                severity=severity,
                details="\n".join(details),
                is_problem=is_problem,
                recommendation="\n".join(security_concerns) if security_concerns else None
            ))
            
        return issues
    
    def _check_network_activity(self, header) -> List[SecurityIssue]:
        """Проверка сетевой активности в бинарном файле"""
        issues = []
        
        # Список сетевых функций и символов
        network_functions = {
            # Сокеты
            'socket': 'Создание сетевых сокетов',
            'connect': 'Установка сетевых соединений',
            'bind': 'Привязка к сетевому порту',
            'listen': 'Прослушивание сетевых соединений',
            'accept': 'Принятие сетевых соединений',
            'send': 'Отправка данных по сети',
            'recv': 'Получение данных по сети',
            
            # HTTP/HTTPS
            'http': 'HTTP операции',
            'https': 'HTTPS операции',
            'curl': 'HTTP запросы через libcurl',
            'CFNetwork': 'Сетевые операции через CFNetwork',
            'webkit': 'WebKit сетевые операции',
            'url': 'URL операции',
            'request': 'HTTP запросы',
            'response': 'HTTP ответы',
            'download': 'Загрузка данных',
            'upload': 'Отправка данных',
            
            # DNS
            'dns': 'DNS операции',
            'resolv': 'DNS резолвинг',
            'getaddrinfo': 'Получение адресов',
            'gethostbyname': 'Получение хоста по имени',
            'host': 'Работа с хостами',
            'domain': 'Работа с доменами',
            
            # Сетевые протоколы
            'tcp': 'TCP соединения',
            'udp': 'UDP соединения',
            'ssl': 'SSL/TLS операции',
            'tls': 'TLS операции',
            'websocket': 'WebSocket соединения',
            'quic': 'QUIC протокол',
            'spdy': 'SPDY протокол',
            
            # Сетевые утилиты
            'ping': 'Проверка доступности хоста',
            'netstat': 'Просмотр сетевых соединений',
            'ifconfig': 'Конфигурация сетевых интерфейсов',
            'route': 'Управление маршрутизацией',
            'network': 'Сетевые операции',
            'connection': 'Управление соединениями',
            'stream': 'Сетевые потоки',
            'proxy': 'Работа с прокси',
            'cache': 'Сетевой кэш',
            
            # Safari специфичные
            'safari': 'Safari сетевые операции',
            'webkit': 'WebKit сетевые операции',
            'cfnetwork': 'Core Foundation Network',
            'cfurl': 'Core Foundation URL',
            'cfhttp': 'Core Foundation HTTP',
            'cfstream': 'Core Foundation Stream',
            'cfnet': 'Core Foundation Network',
            'cfnetworking': 'Core Foundation Networking',
            'cfnetdiagnostics': 'Core Foundation Network Diagnostics',
            'cfnetmonitor': 'Core Foundation Network Monitor',
            'cfnetsecurity': 'Core Foundation Network Security',
            'cfnetssl': 'Core Foundation Network SSL',
            'cfnettls': 'Core Foundation Network TLS',
            'cfnetws': 'Core Foundation Network WebSocket',
            'cfnetquic': 'Core Foundation Network QUIC',
            'cfnetspdy': 'Core Foundation Network SPDY',
            'cfnetcache': 'Core Foundation Network Cache',
            'cfnetproxy': 'Core Foundation Network Proxy',
            'cfnetconnection': 'Core Foundation Network Connection',
            'cfneturl': 'Core Foundation Network URL',
            'cfnetrequest': 'Core Foundation Network Request',
            'cfnetresponse': 'Core Foundation Network Response',
            'cfnetdownload': 'Core Foundation Network Download',
            'cfnetupload': 'Core Foundation Network Upload',
            
            # Chrome специфичные
            'chrome': 'Chrome сетевые операции',
            'chromium': 'Chromium сетевые операции',
            'blink': 'Blink сетевые операции',
            'v8': 'V8 сетевые операции',
            'mojo': 'Mojo сетевые операции',
            'net': 'Chrome Network Stack',
            'url': 'Chrome URL',
            'http': 'Chrome HTTP',
            'https': 'Chrome HTTPS',
            'ssl': 'Chrome SSL',
            'tls': 'Chrome TLS',
            'websocket': 'Chrome WebSocket',
            'quic': 'Chrome QUIC',
            'spdy': 'Chrome SPDY',
            'proxy': 'Chrome Proxy',
            'cache': 'Chrome Cache',
            'dns': 'Chrome DNS',
            'socket': 'Chrome Socket',
            'stream': 'Chrome Stream',
            'connection': 'Chrome Connection',
            'request': 'Chrome Request',
            'response': 'Chrome Response',
            'download': 'Chrome Download',
            'upload': 'Chrome Upload'
        }
        
        # Список сетевых библиотек
        network_libraries = {
            # Фреймворки
            'WebKit.framework': 'WebKit операции',
            'CFNetwork.framework': 'Core Foundation сетевые операции',
            'Network.framework': 'Низкоуровневые сетевые операции',
            'NetworkExtension.framework': 'Сетевые расширения',
            'SafariServices.framework': 'Safari сервисы',
            
            # Системные приватные фреймворки
            'CoreAnalytics.framework': 'Аналитика и сетевая активность',
            'NetworkStatistics.framework': 'Статистика сети',
            'NetworkServiceProxy.framework': 'Сетевые прокси',
            'NetworkDiagnostics.framework': 'Диагностика сети',
            
            # Системные библиотеки
            'libresolv': 'DNS операции',
            'libresolv.9': 'DNS операции (версия 9)',
            'libsystem_networkextension': 'Сетевые расширения'
        }
        
        # Проверяем символы
        symbol_analyzer = SymbolAnalyzer(self.macho, self.file_path)
        symbols, libraries = symbol_analyzer.analyze()
        
        # Ищем сетевые функции
        network_symbols = []
        for symbol in symbols:
            for func_name, description in network_functions.items():
                if func_name in symbol.name.lower():
                    network_symbols.append((symbol.name, description))
        
        # Ищем сетевые библиотеки
        network_libs = []
        for lib in libraries:
            for lib_name, description in network_libraries.items():
                if lib_name in lib.name.lower():
                    network_libs.append((lib.name, description))
        
        # Формируем отчет
        details = []
        
        if network_symbols or network_libs:
            details.append("Обнаружена сетевая активность:")
            
            if network_symbols:
                details.append("\nСетевые функции:")
                for func_name, description in network_symbols:
                    details.append(f"  - {func_name}")
                    details.append(f"    Назначение: {description}")
            
            if network_libs:
                details.append("\nСетевые библиотеки:")
                for lib_name, description in network_libs:
                    details.append(f"  - {lib_name}")
                    details.append(f"    Назначение: {description}")
            
            # Определяем уровень риска
            risk_level = SeverityLevel.WARNING
            risk_details = []
            
            # Проверяем наличие потенциально опасных функций
            dangerous_functions = {'socket', 'connect', 'bind', 'listen', 'accept'}
            for func_name, _ in network_symbols:
                if any(danger in func_name.lower() for danger in dangerous_functions):
                    risk_level = SeverityLevel.CRITICAL
                    risk_details.append(f"Обнаружены функции для создания сетевых соединений: {func_name}")
            
            # Проверяем наличие приватных сетевых библиотек
            private_network_libs = [lib for lib, _ in network_libs if 'private' in lib.lower()]
            if private_network_libs:
                risk_details.append(f"Используются приватные сетевые библиотеки: {', '.join(private_network_libs)}")
            
            issues.append(SecurityIssue(
                description="Сетевая активность",
                severity=risk_level,
                details="\n".join(details),
                is_problem=True,
                recommendation="\n".join(risk_details) if risk_details else None
            ))
        else:
            issues.append(SecurityIssue(
                description="Сетевая активность",
                severity=SeverityLevel.INFO,
                details="Сетевая активность не обнаружена",
                is_problem=False,
                recommendation=None
            ))
        
        return issues

    def _check_debug_info(self, header) -> List[SecurityIssue]:
        """Проверка наличия отладочной информации"""
        issues = []
        debug_analyzer = DebugAnalyzer(self.macho, self.file_path)
        debug_info = debug_analyzer.analyze()
        
        if debug_info.has_debug_symbols or debug_info.has_dwarf_info:
            details = []
            if debug_info.has_debug_symbols:
                details.append("отладочные символы")
            if debug_info.has_dwarf_info:
                details.append("DWARF информация")
            
            issues.append(SecurityIssue(
                description="Наличие отладочной информации",
                details=f"Обнаружена отладочная информация: {', '.join(details)}",
                severity=SeverityLevel.INFO,
                recommendation="Рекомендуется удалить отладочную информацию перед релизом",
                is_problem=False
            ))
        return issues
        
    def _check_vulnerable_functions(self, header) -> List[SecurityIssue]:
        """Проверка наличия уязвимых функций"""
        issues = []
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
                    
                # Читаем таблицу строк
                with open(self.file_path, 'rb') as f:
                    f.seek(strtab.stroff)
                    string_table = f.read(strtab.strsize)
                    
                    # Проверяем наличие уязвимых функций
                    for func_name in self.vulnerable_functions:
                        if func_name.encode() in string_table:
                            issues.append(SecurityIssue(
                                description=self.vulnerable_functions[func_name],
                                details=f"Обнаружено использование функции {func_name}",
                                severity=SeverityLevel.WARNING,
                                recommendation=f"Рекомендуется использовать безопасную альтернативу {func_name} (например, gets_s, strcpy_s)",
                                is_problem=True
                            ))
        return issues
        
    def _check_anti_debug(self, header) -> List[SecurityIssue]:
        """Проверка наличия антиотладочных техник"""
        issues = []
        
        # Проверяем наличие известных антиотладочных функций
        anti_debug_functions = [
            'ptrace',           # Прямой вызов ptrace
            'sysctl',          # Проверка через sysctl
            'task_for_pid',    # Проверка через task_for_pid
            'fork',            # Проверка через fork
            'getppid',         # Проверка родительского процесса
            'isatty',          # Проверка через isatty
            'ioctl',           # Проверка через ioctl
            'syscall',         # Прямой вызов syscall
            'mach_task_self',  # Проверка через mach_task_self
            'mach_thread_self' # Проверка через mach_thread_self
        ]
        
        for function in anti_debug_functions:
            if self._find_symbol(function):
                issues.append(SecurityIssue(
                    description=f"Обнаружена антиотладочная функция: {function}",
                    severity=SeverityLevel.WARNING,
                    details=f"Найдена функция {function}, которая может использоваться для обнаружения отладчика",
                    is_problem=True
                ))

        # Проверяем наличие строк, связанных с отладкой
        debug_strings = [
            b'debug',
            b'gdb',
            b'lldb',
            b'xcode',
            b'debugger',
            b'ptrace',
            b'IDA',
            b'Hopper',
            b'radare2',
            b'Ghidra'
        ]
        
        for cmd in header.commands:
            if cmd[0].cmd == LC_SEGMENT_64:
                segment = cmd[1]
                sections = cmd[2]
                for section in sections:
                    try:
                        with open(self.file_path, 'rb') as f:
                            f.seek(section.offset)
                            data = f.read(section.size)
                            if data:
                                for string in debug_strings:
                                    if string in data:
                                        section_name = section.sectname.decode('utf-8').rstrip('\x00')
                                        string_value = string.decode('utf-8', errors='ignore')
                                        issues.append(SecurityIssue(
                                            description="Обнаружены строки, связанные с отладкой",
                                            severity=SeverityLevel.WARNING,
                                            details=f"Найдена строка {string_value} в секции {section_name}",
                                            is_problem=True
                                        ))
                    except (IOError, OSError) as e:
                        section_name = section.sectname.decode('utf-8').rstrip('\x00')
                        issues.append(SecurityIssue(
                            description="Ошибка при анализе строк",
                            severity=SeverityLevel.WARNING,
                            details=f"Не удалось прочитать секцию {section_name}: {str(e)}",
                            is_problem=True
                        ))

        # Проверяем наличие сигналов, связанных с отладкой
        debug_signals = [
            'SIGTRAP',
            'SIGSTOP',
            'SIGTSTP',
            'SIGTTIN',
            'SIGTTOU'
        ]
        
        for signal in debug_signals:
            if self._find_symbol(signal):
                issues.append(SecurityIssue(
                    description=f"Обнаружен сигнал отладки: {signal}",
                    severity=SeverityLevel.WARNING,
                    details=f"Найден сигнал {signal}, который может использоваться для обнаружения отладчика",
                    is_problem=True
                ))

        # Проверяем наличие проверок времени выполнения
        timing_functions = [
            'mach_absolute_time',
            'gettimeofday',
            'clock_gettime',
            'time'
        ]
        
        for function in timing_functions:
            if self._find_symbol(function):
                issues.append(SecurityIssue(
                    description=f"Обнаружена функция измерения времени: {function}",
                    severity=SeverityLevel.WARNING,
                    details=f"Найдена функция {function}, которая может использоваться для обнаружения замедления при отладке",
                    is_problem=True
                ))

        if not issues:
            issues.append(SecurityIssue(
                description="Антиотладочные техники не обнаружены",
                severity=SeverityLevel.INFO,
                details="Не найдено признаков использования антиотладочных техник",
                is_problem=False
            ))

        return issues

    def _check_safe_stack(self) -> List[SecurityIssue]:
        issues = []
        
        # Safe Stack не поддерживается на macOS ARM64
        if self.macho.headers[0].header.cputype == CPU_TYPE_ARM64:
            issues.append(SecurityIssue(
                description="Safe Stack не поддерживается",
                details="Safe Stack не поддерживается на macOS ARM64",
                severity=SeverityLevel.INFO,
                recommendation="Safe Stack доступен только на x86_64 macOS",
                is_problem=False
            ))
            return issues
        
        # Проверяем наличие секции __safestack
        has_safestack_section = False
        for cmd in self.macho.headers[0].commands:
            if cmd[0].cmd == LC_SEGMENT_64:
                for section in cmd[2]:
                    if section.sectname.decode('utf-8').rstrip('\x00') == "__safestack":
                        has_safestack_section = True
                        break
            if has_safestack_section:
                break
        
        # Проверяем наличие символов Safe Stack
        has_safestack_symbols = False
        for cmd in self.macho.headers[0].commands:
            if cmd[0].cmd == LC_SYMTAB:
                symtab = cmd[1]
                try:
                    with open(self.file_path, 'rb') as f:
                        f.seek(symtab.stroff)
                        string_table = f.read(symtab.strsize)
                        
                        if string_table:
                            strings = string_table.decode('utf-8', errors='ignore')
                            safe_stack_symbols = [
                                '__safestack_init',
                                '__safestack_pointer',
                                '__safestack_guard',
                                '__safestack_check'
                            ]
                            for symbol in safe_stack_symbols:
                                if symbol in strings:
                                    has_safestack_symbols = True
                                    break
                except (IOError, OSError):
                    continue
        
        if has_safestack_section and has_safestack_symbols:
            issues.append(SecurityIssue(
                description="Safe Stack включен",
                details="Обнаружена защита Safe Stack",
                severity=SeverityLevel.INFO,
                recommendation="Safe Stack успешно включен",
                is_problem=False
            ))
        else:
            issues.append(SecurityIssue(
                description="Отсутствует Safe Stack",
                details="Отсутствует защита Safe Stack",
                severity=SeverityLevel.WARNING,
                recommendation="Рекомендуется включить -fsanitize=safe-stack при компиляции (только для x86_64)",
                is_problem=True
            ))
        
        return issues

    def analyze(self, target_header) -> List[SecurityIssue]:
        """Проведение полного анализа безопасности"""
        issues = []
        
        # Базовые проверки безопасности
        issues.extend(self._check_base_security(target_header))
        
        # Проверка механизмов защиты
        issues.extend(self._check_ASLR_mechanism(target_header))
        issues.extend(self._check_nx(target_header))
        issues.extend(self._check_relro(target_header))
        issues.extend(self._check_fortify_source(target_header))
        issues.extend(self.__check_stack_canary(target_header))
        issues.extend(self._check_canaries(target_header))  # Добавляем проверку канареек
        
        # Проверка подписи кода
        issues.extend(self._check_code_signing())
        
        # Проверка шифрования
        issues.extend(self._check_encryption(target_header))
        
        # Проверка символов и импортов
        issues.extend(self._check_symbols_and_imports())
        
        # Проверка сетевой активности
        issues.extend(self._check_network_activity(target_header))
        
        # Проверка отладочной информации
        issues.extend(self._check_debug_info(target_header))
        
        # Проверка уязвимых функций
        issues.extend(self._check_vulnerable_functions(target_header))
        
        # Проверка антиотладочных техник
        issues.extend(self._check_anti_debug(target_header))
        
        # Проверка safe stack
        issues.extend(self._check_safe_stack())
        
        return issues 