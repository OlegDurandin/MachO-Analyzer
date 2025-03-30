from typing import Dict, Any, List
from core.plugin_base import MachOPlugin
from core.security_analyzer import SecurityAnalyzer, SecurityIssue, SeverityLevel
from macholib.mach_o import (
    MH_ALLOW_STACK_EXECUTION,
    MH_NO_HEAP_EXECUTION,
    MH_PIE,
    MH_NO_REEXPORTED_DYLIBS,
    MH_APP_EXTENSION_SAFE,
    MH_NOUNDEFS,
    S_ATTR_SOME_INSTRUCTIONS,
    LC_SEGMENT,
    LC_SEGMENT_64,
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
    LC_SYMTAB
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.constants import VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE, CPU_TYPE_ARM64
from core.sign_analyzer import SignAnalyzer, SignStatus, SignType
from core.symbol_analyzer import SymbolAnalyzer, SymbolType
from core.debug_analyzer import DebugAnalyzer

console = Console()

class SecurityAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа безопасности Mach-O файла"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.security_analyzer = SecurityAnalyzer(self.macho, file_path)
        
        # Определяем числовые значения для уровней риска
        self.risk_levels = {
            SeverityLevel.INFO: 0,
            SeverityLevel.WARNING: 1,
            SeverityLevel.CRITICAL: 2
        }
        
        # Список уязвимых функций
        self.vulnerable_functions = {
            'gets': 'Использование небезопасной функции gets()',
            'strcpy': 'Использование небезопасной функции strcpy()',
            'strcat': 'Использование небезопасной функции strcat()',
            'sprintf': 'Использование небезопасной функции sprintf()',
            'vsprintf': 'Использование небезопасной функции vsprintf()'
        }
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует безопасность Mach-O файла"""
        results = {
            "basic_info": {
                "total_issues": 0,
                "critical_count": 0,
                "warning_count": 0,
                "info_count": 0,
                "risk_level": SeverityLevel.INFO
            },
            "security_analysis": {
                "header_flags": {},
                "executable_sections": [],
                "technical_details": {}
            },
            "risk_assessment": {
                "level": SeverityLevel.INFO,
                "reasons": [],
                "recommendations": []
            }
        }
        
        # Получаем первый заголовок для анализа
        if not self.macho.headers:
            console.print("[red]Ошибка: Файл не содержит заголовков Mach-O[/red]")
            return results
            
        header = self.macho.headers[0]
        
        # Проверяем наличие таблицы символов
        has_symtab = False
        for cmd in header.commands:
            if cmd[0].cmd == LC_SYMTAB:
                has_symtab = True
                break
                
        if not has_symtab:
            console.print("[yellow]Предупреждение: Файл не содержит таблицы символов[/yellow]")
            results["security_analysis"]["symbols"] = {
                "enabled": False,
                "severity": SeverityLevel.WARNING,
                "description": "Отсутствует таблица символов",
                "details": "Файл не содержит таблицы символов, некоторые проверки могут быть недоступны",
                "recommendation": "Рекомендуется компилировать с отладочными символами для полного анализа"
            }
            results["basic_info"]["warning_count"] += 1
        
        try:
            # Анализ заголовков
            # Проверяем флаги заголовка
            self._analyze_header_flags(header, results)
            
            # Проверяем сегменты на наличие исполняемых секций
            for cmd in header.commands:
                if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    for sect in cmd[2]:
                        if sect.flags & S_ATTR_SOME_INSTRUCTIONS:
                            sect_name = sect.sectname.decode('utf-8').strip('\x00')
                            results["security_analysis"]["executable_sections"].append({
                                "name": sect_name,
                                "flags": sect.flags
                            })
                            results["basic_info"]["warning_count"] += 1
            
            # Проверка механизмов защиты
            self._check_security_mechanisms(header, results)
            
            # Проверка подписи кода
            self._check_code_signing(results)
            
            # Проверка шифрования
            self._check_encryption(header, results)
            
            # Проверка символов и импортов
            self._check_symbols_and_imports(results)
            
            # Проверка сетевой активности
            self._check_network_activity(header, results)
            
            # Проверка отладочной информации
            self._check_debug_info(header, results)
            
            # Проверка уязвимых функций
            self._check_vulnerable_functions(header, results)
            
            # Проверка антиотладочных техник
            self._check_anti_debug(header, results)
            
            # Проверка safe stack
            self._check_safe_stack(results)
            
            # Оценка рисков
            self._assess_risks(results)
            
        except Exception as e:
            console.print(f"[red]Ошибка при анализе безопасности: {str(e)}[/red]")
            results["basic_info"]["critical_count"] += 1
            results["risk_assessment"]["level"] = SeverityLevel.CRITICAL
            results["risk_assessment"]["reasons"].append(f"Ошибка анализа: {str(e)}")
        
        return results
    
    def _check_security_mechanisms(self, header: Any, results: Dict[str, Any]) -> None:
        """Проверка механизмов защиты"""
        # Проверка ASLR
        if not (header.header.flags & MH_PIE):
            results["security_analysis"]["header_flags"]["aslr"] = {
                "enabled": False,
                "severity": SeverityLevel.CRITICAL,
                "description": "Отключен ASLR (Address Space Layout Randomization)",
                "details": "Флаг MH_PIE не установлен в заголовке файла",
                "recommendation": "Включить ASLR для предотвращения атак на переполнение буфера"
            }
            results["basic_info"]["critical_count"] += 1
        
        # Проверка NX
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                seg = cmd[1]
                segname = seg.segname.decode('utf-8').rstrip('\x00')
                if segname == '__DATA' and seg.maxprot & VM_PROT_EXECUTE:
                    results["security_analysis"]["header_flags"]["nx"] = {
                        "enabled": False,
                        "severity": SeverityLevel.WARNING,
                        "description": "Сегмент данных исполняемый",
                        "details": f"Сегмент {segname} имеет права на выполнение",
                        "recommendation": "Отключить выполнение кода в сегменте данных"
                    }
                    results["basic_info"]["warning_count"] += 1
        
        # Проверка RELRO
        has_data_const = False
        has_got_protection = False
        for cmd in header.commands:
            if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                seg = cmd[1]
                segname = seg.segname.decode('utf-8').rstrip('\x00')
                if segname == '__DATA_CONST':
                    has_data_const = True
                    if (seg.initprot & VM_PROT_WRITE) and not (seg.maxprot & VM_PROT_WRITE):
                        has_got_protection = True
        
        if not has_data_const or not has_got_protection:
            results["security_analysis"]["header_flags"]["relro"] = {
                "enabled": False,
                "severity": SeverityLevel.WARNING,
                "description": "Отключен RELRO",
                "details": "Отсутствует защита GOT от перезаписи",
                "recommendation": "Включить RELRO при компиляции"
            }
            results["basic_info"]["warning_count"] += 1

    def _check_code_signing(self, results: Dict[str, Any]) -> None:
        """Проверка подписи кода"""
        sign_analyzer = SignAnalyzer(self.file_path)
        sign_info = sign_analyzer.analyze()
        
        if sign_info.status == SignStatus.NOT_SIGNED:
            results["security_analysis"]["code_signing"] = {
                "enabled": False,
                "severity": SeverityLevel.WARNING,
                "description": "Отсутствует подпись кода",
                "details": "Файл не подписан",
                "recommendation": "Подписать файл для улучшения безопасности"
            }
            results["basic_info"]["warning_count"] += 1
        elif sign_info.status == SignStatus.INVALID:
            results["security_analysis"]["code_signing"] = {
                "enabled": False,
                "severity": SeverityLevel.CRITICAL,
                "description": "Недействительная подпись кода",
                "details": sign_info.details,
                "recommendation": "Проверить целостность подписи и сертификаты"
            }
            results["basic_info"]["critical_count"] += 1

    def _check_encryption(self, header: Any, results: Dict[str, Any]) -> None:
        """Проверка шифрования"""
        for cmd in header.commands:
            if cmd[0].cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                if cmd[1].cryptid == 1:
                    results["security_analysis"]["encryption"] = {
                        "enabled": True,
                        "severity": SeverityLevel.INFO,
                        "description": "Файл зашифрован",
                        "details": "Обнаружено шифрование",
                        "recommendation": None
                    }
                    results["basic_info"]["info_count"] += 1
                else:
                    results["security_analysis"]["encryption"] = {
                        "enabled": False,
                        "severity": SeverityLevel.WARNING,
                        "description": "Отсутствует шифрование",
                        "details": "Файл содержит сегмент шифрования, но не зашифрован",
                        "recommendation": "Возможно, файл расшифрован или требует шифрования"
                    }
                    results["basic_info"]["warning_count"] += 1

    def _check_symbols_and_imports(self, results: Dict[str, Any]) -> None:
        """Проверка символов и импортов"""
        symbol_analyzer = SymbolAnalyzer(self.macho, self.file_path)
        symbols, libraries = symbol_analyzer.analyze()
        
        # Проверка слабых символов
        weak_symbols = [s for s in symbols if s.is_weak]
        if weak_symbols:
            results["security_analysis"]["weak_symbols"] = {
                "enabled": True,
                "severity": SeverityLevel.WARNING,
                "description": "Обнаружены слабые символы",
                "details": f"Найдено {len(weak_symbols)} слабых символов",
                "recommendation": "Проверить использование слабых символов"
            }
            results["basic_info"]["warning_count"] += 1
        
        # Проверка неопределенных символов
        undefined_symbols = [s for s in symbols if s.is_undefined]
        if undefined_symbols:
            results["security_analysis"]["undefined_symbols"] = {
                "enabled": True,
                "severity": SeverityLevel.WARNING,
                "description": "Обнаружены неопределенные символы",
                "details": f"Найдено {len(undefined_symbols)} неопределенных символов",
                "recommendation": "Проверить все зависимости"
            }
            results["basic_info"]["warning_count"] += 1

    def _check_network_activity(self, header: Any, results: Dict[str, Any]) -> None:
        """Проверка сетевой активности"""
        network_functions = {
            'socket': 'Создание сетевых сокетов',
            'connect': 'Установка сетевых соединений',
            'bind': 'Привязка к сетевому порту',
            'listen': 'Прослушивание сетевых соединений',
            'accept': 'Принятие сетевых соединений',
            'send': 'Отправка данных по сети',
            'recv': 'Получение данных по сети'
        }
        
        found_network_functions = []
        
        # Находим таблицу символов
        symtab_cmd = None
        for cmd in header.commands:
            if cmd[0].cmd == LC_SYMTAB:
                symtab_cmd = cmd[1]
                break
                
        if not symtab_cmd:
            return
            
        try:
            with open(self.file_path, 'rb') as f:
                # Читаем таблицу строк
                f.seek(symtab_cmd.stroff)
                string_table = f.read(symtab_cmd.strsize)
                
                # Декодируем таблицу строк
                decoded_strings = string_table.decode('utf-8', errors='ignore')
                
                # Ищем сетевые функции
                for func_name in network_functions:
                    if func_name in decoded_strings:
                        found_network_functions.append(func_name)
                        
        except (IOError, OSError) as e:
            console.print(f"[red]Ошибка при чтении таблицы символов: {str(e)}[/red]")
            return
        
        if found_network_functions:
            results["security_analysis"]["network_activity"] = {
                "enabled": True,
                "severity": SeverityLevel.WARNING,
                "description": "Обнаружена сетевая активность",
                "details": f"Найдены сетевые функции: {', '.join(found_network_functions)}",
                "recommendation": "Проверить безопасность сетевых операций"
            }
            results["basic_info"]["warning_count"] += 1

    def _check_debug_info(self, header: Any, results: Dict[str, Any]) -> None:
        """Проверка отладочной информации"""
        debug_analyzer = DebugAnalyzer(self.macho, self.file_path)
        debug_info = debug_analyzer.analyze()
        
        if debug_info.has_debug_symbols or debug_info.has_dwarf_info:
            details = []
            if debug_info.has_debug_symbols:
                details.append("отладочные символы")
            if debug_info.has_dwarf_info:
                details.append("DWARF информация")
            
            results["security_analysis"]["debug_info"] = {
                "enabled": True,
                "severity": SeverityLevel.INFO,
                "description": "Наличие отладочной информации",
                "details": f"Обнаружена отладочная информация: {', '.join(details)}",
                "recommendation": "Рекомендуется удалить отладочную информацию перед релизом"
            }
            results["basic_info"]["info_count"] += 1

    def _check_vulnerable_functions(self, header: Any, results: Dict[str, Any]) -> None:
        """Проверка уязвимых функций"""
        found_vulnerable_functions = []
        
        # Находим таблицу символов
        symtab_cmd = None
        for cmd in header.commands:
            if cmd[0].cmd == LC_SYMTAB:
                symtab_cmd = cmd[1]
                break
                
        if not symtab_cmd:
            return
            
        try:
            with open(self.file_path, 'rb') as f:
                # Читаем таблицу строк
                f.seek(symtab_cmd.stroff)
                string_table = f.read(symtab_cmd.strsize)
                
                # Декодируем таблицу строк
                decoded_strings = string_table.decode('utf-8', errors='ignore')
                
                # Ищем уязвимые функции
                for func_name in self.vulnerable_functions:
                    if func_name in decoded_strings:
                        found_vulnerable_functions.append(func_name)
                        
        except (IOError, OSError) as e:
            console.print(f"[red]Ошибка при чтении таблицы символов: {str(e)}[/red]")
            return
        
        if found_vulnerable_functions:
            results["security_analysis"]["vulnerable_functions"] = {
                "enabled": True,
                "severity": SeverityLevel.WARNING,
                "description": "Обнаружены уязвимые функции",
                "details": f"Найдены уязвимые функции: {', '.join(found_vulnerable_functions)}",
                "recommendation": "Заменить уязвимые функции на безопасные альтернативы"
            }
            results["basic_info"]["warning_count"] += 1

    def _check_anti_debug(self, header: Any, results: Dict[str, Any]) -> None:
        """Проверка антиотладочных техник"""
        anti_debug_functions = [
            'ptrace',
            'sysctl',
            'task_for_pid',
            'fork',
            'getppid',
            'isatty',
            'ioctl',
            'syscall',
            'mach_task_self',
            'mach_thread_self'
        ]
        
        found_anti_debug_functions = []
        
        # Находим таблицу символов
        symtab_cmd = None
        for cmd in header.commands:
            if cmd[0].cmd == LC_SYMTAB:
                symtab_cmd = cmd[1]
                break
                
        if not symtab_cmd:
            return
            
        try:
            with open(self.file_path, 'rb') as f:
                # Читаем таблицу строк
                f.seek(symtab_cmd.stroff)
                string_table = f.read(symtab_cmd.strsize)
                
                # Декодируем таблицу строк
                decoded_strings = string_table.decode('utf-8', errors='ignore')
                
                # Ищем антиотладочные функции
                for func_name in anti_debug_functions:
                    if func_name in decoded_strings:
                        found_anti_debug_functions.append(func_name)
                        
        except (IOError, OSError) as e:
            console.print(f"[red]Ошибка при чтении таблицы символов: {str(e)}[/red]")
            return
        
        if found_anti_debug_functions:
            results["security_analysis"]["anti_debug"] = {
                "enabled": True,
                "severity": SeverityLevel.WARNING,
                "description": "Обнаружены антиотладочные техники",
                "details": f"Найдены антиотладочные функции: {', '.join(found_anti_debug_functions)}",
                "recommendation": "Проверить необходимость антиотладочных техник"
            }
            results["basic_info"]["warning_count"] += 1

    def _check_safe_stack(self, results: Dict[str, Any]) -> None:
        """Проверка safe stack"""
        if self.macho.headers[0].header.cputype == CPU_TYPE_ARM64:
            results["security_analysis"]["safe_stack"] = {
                "enabled": False,
                "severity": SeverityLevel.INFO,
                "description": "Safe Stack не поддерживается",
                "details": "Safe Stack не поддерживается на macOS ARM64",
                "recommendation": "Safe Stack доступен только на x86_64 macOS"
            }
            results["basic_info"]["info_count"] += 1
            return
        
        has_safestack_section = False
        for cmd in self.macho.headers[0].commands:
            if cmd[0].cmd == LC_SEGMENT_64:
                for section in cmd[2]:
                    if section.sectname.decode('utf-8').rstrip('\x00') == "__safestack":
                        has_safestack_section = True
                        break
            if has_safestack_section:
                break
        
        if not has_safestack_section:
            results["security_analysis"]["safe_stack"] = {
                "enabled": False,
                "severity": SeverityLevel.WARNING,
                "description": "Отсутствует Safe Stack",
                "details": "Отсутствует защита Safe Stack",
                "recommendation": "Включить -fsanitize=safe-stack при компиляции (только для x86_64)"
            }
            results["basic_info"]["warning_count"] += 1

    def _analyze_header_flags(self, header: Any, results: Dict[str, Any]) -> None:
        """Анализирует флаги заголовка на проблемы безопасности"""
        # Проверяем флаг PIE
        if not (header.header.flags & MH_PIE):
            results["security_analysis"]["header_flags"]["pie"] = {
                "enabled": False,
                "severity": SeverityLevel.CRITICAL,
                "description": "Отключен ASLR (Address Space Layout Randomization)",
                "details": "Флаг MH_PIE не установлен в заголовке файла",
                "recommendation": "Включить ASLR для предотвращения атак на переполнение буфера"
            }
            results["basic_info"]["critical_count"] += 1
        
        # Проверяем флаг NOUNDEFS
        if not (header.header.flags & MH_NOUNDEFS):
            results["security_analysis"]["header_flags"]["noundefs"] = {
                "enabled": False,
                "severity": SeverityLevel.WARNING,
                "description": "Файл содержит неопределенные символы",
                "details": "Флаг MH_NOUNDEFS не установлен в заголовке файла",
                "recommendation": "Проверить все зависимости и убедиться, что все символы определены"
            }
            results["basic_info"]["warning_count"] += 1
        
        # Проверяем флаг ALLOW_STACK_EXECUTION
        if header.header.flags & MH_ALLOW_STACK_EXECUTION:
            results["security_analysis"]["header_flags"]["stack_execution"] = {
                "enabled": True,
                "severity": SeverityLevel.CRITICAL,
                "description": "Разрешено выполнение кода в стеке",
                "details": "Флаг MH_ALLOW_STACK_EXECUTION установлен в заголовке файла",
                "recommendation": "Отключить выполнение кода в стеке для предотвращения атак"
            }
            results["basic_info"]["critical_count"] += 1
        
        # Проверяем флаг NO_HEAP_EXECUTION
        if header.header.flags & MH_NO_HEAP_EXECUTION:
            results["security_analysis"]["header_flags"]["heap_execution"] = {
                "enabled": True,
                "severity": SeverityLevel.INFO,
                "description": "Запрещено выполнение кода в куче",
                "details": "Флаг MH_NO_HEAP_EXECUTION установлен в заголовке файла",
                "recommendation": "Рекомендуется оставить этот флаг для дополнительной безопасности"
            }
            results["basic_info"]["info_count"] += 1
        
        # Проверяем флаг NO_REEXPORTED_DYLIBS
        if not (header.header.flags & MH_NO_REEXPORTED_DYLIBS):
            results["security_analysis"]["header_flags"]["reexported_dylibs"] = {
                "enabled": False,
                "severity": SeverityLevel.WARNING,
                "description": "Разрешено реэкспортирование динамических библиотек",
                "details": "Флаг MH_NO_REEXPORTED_DYLIBS не установлен в заголовке файла",
                "recommendation": "Ограничить реэкспортирование библиотек для предотвращения DLL-инъекций"
            }
            results["basic_info"]["warning_count"] += 1
        
        # Проверяем флаг APP_EXTENSION_SAFE
        if header.header.flags & MH_APP_EXTENSION_SAFE:
            results["security_analysis"]["header_flags"]["app_extension_safe"] = {
                "enabled": True,
                "severity": SeverityLevel.INFO,
                "description": "Приложение безопасно для расширений",
                "details": "Флаг MH_APP_EXTENSION_SAFE установлен в заголовке файла",
                "recommendation": "Рекомендуется оставить этот флаг для дополнительной безопасности"
            }
            results["basic_info"]["info_count"] += 1
    
    def _assess_risks(self, results: Dict[str, Any]) -> None:
        """Оценивает риски на основе анализа"""
        risk_level = SeverityLevel.INFO
        reasons = []
        recommendations = []
        
        # Оценка на основе критических проблем
        if results["basic_info"]["critical_count"] > 0:
            risk_level = SeverityLevel.CRITICAL
            reasons.append(f"Обнаружены критические проблемы безопасности ({results['basic_info']['critical_count']})")
            recommendations.append("Требуется немедленное исправление критических проблем")
        
        # Оценка на основе предупреждений
        if results["basic_info"]["warning_count"] > 2:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружено значительное количество предупреждений ({results['basic_info']['warning_count']})")
            recommendations.append("Рекомендуется исправить предупреждения для улучшения безопасности")
        
        # Обновление результатов
        results["basic_info"]["total_issues"] = (
            results["basic_info"]["critical_count"] +
            results["basic_info"]["warning_count"] +
            results["basic_info"]["info_count"]
        )
        results["basic_info"]["risk_level"] = risk_level
        results["risk_assessment"].update({
            "level": risk_level,
            "reasons": reasons,
            "recommendations": recommendations
        })
    
    def _print_security_info(self, info: Dict[str, Any]) -> None:
        """Выводит информацию о безопасности"""
        try:
            # Основная информация
            basic_info = info["basic_info"]
            console.print("\n[bold magenta]Основная информация о безопасности[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Всего проблем", str(basic_info["total_issues"])],
                ["Критических", str(basic_info["critical_count"])],
                ["Предупреждений", str(basic_info["warning_count"])],
                ["Информационных", str(basic_info["info_count"])],
                ["Уровень риска", str(info["risk_assessment"]["level"])]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Флаги заголовка
            if info["security_analysis"]["header_flags"]:
                console.print("\n[bold cyan]Флаги заголовка[/bold cyan]")
                flags_table = Table(show_header=True, header_style="bold cyan")
                flags_table.add_column("Флаг", style="cyan")
                flags_table.add_column("Статус", style="yellow")
                flags_table.add_column("Уровень", style="red")
                flags_table.add_column("Описание", style="green")
                flags_table.add_column("Рекомендация", style="yellow")
                
                for flag_name, flag_info in info["security_analysis"]["header_flags"].items():
                    style = "red" if flag_info["severity"] == SeverityLevel.CRITICAL else "yellow" if flag_info["severity"] == SeverityLevel.WARNING else "green"
                    flags_table.add_row(
                        flag_name.replace("_", " ").title(),
                        "Включен" if flag_info["enabled"] else "Отключен",
                        f"[{style}]{flag_info['severity'].value}[/{style}]",
                        flag_info["description"],
                        flag_info["recommendation"]
                    )
                console.print(flags_table)
            
            # Исполняемые секции
            if info["security_analysis"]["executable_sections"]:
                console.print("\n[bold yellow]Исполняемые секции[/bold yellow]")
                sections_table = Table(show_header=True, header_style="bold yellow")
                sections_table.add_column("Имя", style="cyan")
                sections_table.add_column("Флаги", style="yellow")
                sections_table.add_column("Рекомендация", style="green")
                
                for section in info["security_analysis"]["executable_sections"]:
                    sections_table.add_row(
                        section["name"],
                        str(section["flags"]),
                        "Проверить необходимость исполняемых секций"
                    )
                console.print(sections_table)
            
            # Оценка рисков
            if info["risk_assessment"]["reasons"]:
                console.print("\n[bold red]Оценка рисков[/bold red]")
                risk_table = Table(show_header=True, header_style="bold red")
                risk_table.add_column("Уровень", style="cyan")
                risk_table.add_column("Причины", style="yellow")
                risk_table.add_column("Рекомендации", style="green")
                
                risk_table.add_row(
                    str(info["risk_assessment"]["level"]),
                    "\n".join(info["risk_assessment"]["reasons"]),
                    "\n".join(info["risk_assessment"]["recommendations"])
                )
                console.print(risk_table)
                
        except Exception as e:
            console.print(f"[red]Ошибка при выводе информации о безопасности: {str(e)}[/red]")
    
    @staticmethod
    def get_name() -> str:
        return "security_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует безопасность Mach-O файла, включая проверку флагов и защитных механизмов"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 