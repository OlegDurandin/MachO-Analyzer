from typing import Dict, Any, List
from core.plugin_base import MachOPlugin
from macholib.mach_o import *
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.security_analyzer import SeverityLevel

console = Console()

class ImportExportAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа таблиц импорта и экспорта в Mach-O файлах"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.suspicious_imports = [
            "dlopen",
            "dlsym",
            "system",
            "exec",
            "popen",
            "fork",
            "ptrace"
        ]
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует таблицы импорта и экспорта"""
        results = {
            "basic_info": {
                "total_libraries": 0,
                "total_imports": 0,
                "total_exports": 0,
                "suspicious_count": 0
            },
            "imports": {
                "libraries": [],
                "symbols": [],
                "suspicious": []
            },
            "exports": {
                "symbols": [],
                "functions": [],
                "variables": []
            },
            "dynamic_linking": {
                "lazy_bindings": [],
                "non_lazy_bindings": [],
                "weak_bindings": []
            },
            "risk_assessment": {
                "level": SeverityLevel.INFO,
                "reasons": [],
                "recommendations": []
            }
        }
        
        # Анализ каждого заголовка
        for header in self.macho.headers:
            # Анализ команд загрузки
            for cmd in header.commands:
                if cmd[0].cmd == LC_LOAD_DYLIB or cmd[0].cmd == LC_LOAD_WEAK_DYLIB:
                    try:
                        dylib_cmd = cmd[1]
                        lib_path = cmd[2].decode('utf-8').rstrip('\x00')
                        lib_name = lib_path.split('/')[-1] if '/' in lib_path else lib_path
                        
                        results["imports"]["libraries"].append({
                            "path": lib_path,
                            "name": lib_name,
                            "timestamp": dylib_cmd.timestamp,
                            "current_version": dylib_cmd.current_version,
                            "compatibility_version": dylib_cmd.compatibility_version,
                            "weak": cmd[0].cmd == LC_LOAD_WEAK_DYLIB
                        })
                        results["basic_info"]["total_libraries"] += 1
                    except (AttributeError, UnicodeDecodeError) as e:
                        continue
                
                elif cmd[0].cmd == LC_SYMTAB:
                    symtab = cmd[1]
                    with open(self.file_path, 'rb') as f:
                        f.seek(symtab.stroff)
                        strtab = f.read(symtab.strsize)
                        
                        f.seek(symtab.symoff)
                        for i in range(symtab.nsyms):
                            is_64bit = header.header.magic in (MH_MAGIC_64, MH_CIGAM_64)
                            
                            if is_64bit:
                                nlist = nlist_64.from_fileobj(f)
                            else:
                                nlist = nlist.from_fileobj(f)
                            
                            try:
                                strx = nlist.strx if hasattr(nlist, 'strx') else nlist.n_un.n_strx
                                if 0 <= strx < len(strtab):
                                    symbol_name = strtab[strx:strtab.find(b'\x00', strx)].decode('utf-8')
                                    
                                    if nlist.n_type & N_STAB:
                                        continue
                                    
                                    if nlist.n_type & N_PEXT:
                                        if nlist.n_type & N_EXT:
                                            self._analyze_export_symbol(results, symbol_name, nlist)
                                    else:
                                        if nlist.n_type & N_EXT:
                                            self._analyze_import_symbol(results, symbol_name, nlist)
                            except (AttributeError, UnicodeDecodeError):
                                continue
                
                elif cmd[0].cmd == LC_DYSYMTAB:
                    self._analyze_dynamic_symbols(results, cmd[1])
        
        # Обновляем базовую информацию
        results["basic_info"]["total_imports"] = len(results["imports"]["symbols"])
        results["basic_info"]["total_exports"] = len(results["exports"]["symbols"])
        results["basic_info"]["suspicious_count"] = len(results["imports"]["suspicious"])
        
        # Анализ подозрительных импортов и оценка рисков
        self._analyze_suspicious_imports(results)
        self._assess_risks(results)
        
        return results
    
    def _analyze_export_symbol(self, results: Dict[str, Any], symbol_name: str, nlist) -> None:
        """Анализирует экспортируемый символ"""
        symbol_info = {
            "name": symbol_name,
            "address": nlist.n_value,
            "type": self._get_symbol_type(nlist)
        }
        
        if nlist.n_type & N_TYPE == N_SECT:
            # Символ определен в секции
            if nlist.n_desc & N_WEAK_DEF:
                symbol_info["weak"] = True
            
            if "." in symbol_name:
                # Вероятно C++ символ
                symbol_info["mangled"] = True
                symbol_info["demangled"] = self._demangle_symbol(symbol_name)
            
            results["exports"]["symbols"].append(symbol_info)
            
            # Определяем тип экспорта (функция или переменная)
            if self._is_function_symbol(nlist):
                results["exports"]["functions"].append(symbol_info)
            else:
                results["exports"]["variables"].append(symbol_info)
    
    def _analyze_import_symbol(self, results: Dict[str, Any], symbol_name: str, nlist) -> None:
        """Анализирует импортируемый символ"""
        symbol_info = {
            "name": symbol_name,
            "type": self._get_symbol_type(nlist),
            "weak": bool(nlist.n_desc & N_WEAK_REF)
        }
        
        if "." in symbol_name:
            # Вероятно C++ символ
            symbol_info["mangled"] = True
            symbol_info["demangled"] = self._demangle_symbol(symbol_name)
        
        results["imports"]["symbols"].append(symbol_info)
        
        # Проверка на подозрительные импорты
        if any(suspicious in symbol_name for suspicious in self.suspicious_imports):
            results["imports"]["suspicious"].append(symbol_info)
    
    def _analyze_dynamic_symbols(self, results: Dict[str, Any], dysymtab) -> None:
        """Анализирует динамические символы"""
        # Анализ lazy binding
        if dysymtab.nlocrel > 0:
            results["dynamic_linking"]["lazy_bindings"].append({
                "count": dysymtab.nlocrel,
                "offset": dysymtab.locreloff
            })
        
        # Анализ non-lazy binding
        if dysymtab.nextrel > 0:
            results["dynamic_linking"]["non_lazy_bindings"].append({
                "count": dysymtab.nextrel,
                "offset": dysymtab.extreloff
            })
        
        # Анализ weak binding
        if hasattr(dysymtab, 'nindirectsyms') and dysymtab.nindirectsyms > 0:
            results["dynamic_linking"]["weak_bindings"].append({
                "count": dysymtab.nindirectsyms,
                "offset": dysymtab.indirectsymoff
            })
    
    def _analyze_suspicious_imports(self, results: Dict[str, Any]) -> None:
        """Анализирует подозрительные импорты"""
        suspicious_count = len(results["imports"]["suspicious"])
        if suspicious_count > 0:
            results["risk_assessment"]["reasons"].append(
                f"Найдено {suspicious_count} подозрительных импортов"
            )
            
            if suspicious_count > 5:
                results["risk_assessment"]["level"] = SeverityLevel.CRITICAL
            elif suspicious_count > 2:
                results["risk_assessment"]["level"] = SeverityLevel.WARNING
    
    def _assess_risks(self, results: Dict[str, Any]) -> None:
        """Оценивает риски на основе анализа"""
        # Проверка количества импортов
        import_count = len(results["imports"]["symbols"])
        if import_count > 100:
            results["risk_assessment"]["reasons"].append(
                f"Большое количество импортов ({import_count})"
            )
            if results["risk_assessment"]["level"] == SeverityLevel.INFO:
                results["risk_assessment"]["level"] = SeverityLevel.WARNING
        
        # Проверка слабых привязок
        weak_count = sum(1 for sym in results["imports"]["symbols"] if sym.get("weak", False))
        if weak_count > 10:
            results["risk_assessment"]["reasons"].append(
                f"Большое количество слабых привязок ({weak_count})"
            )
            if results["risk_assessment"]["level"] == SeverityLevel.INFO:
                results["risk_assessment"]["level"] = SeverityLevel.WARNING
        
        # Добавление рекомендаций
        if results["risk_assessment"]["level"] != SeverityLevel.INFO:
            results["risk_assessment"]["recommendations"].extend([
                "Проверьте все подозрительные импорты на легитимность",
                "Рассмотрите возможность статической линковки критических функций",
                "Проверьте версии используемых библиотек на известные уязвимости"
            ])
    
    def _get_symbol_type(self, nlist) -> str:
        """Определяет тип символа"""
        if nlist.n_type & N_TYPE == N_UNDF:
            return "undefined"
        elif nlist.n_type & N_TYPE == N_ABS:
            return "absolute"
        elif nlist.n_type & N_TYPE == N_SECT:
            return "section"
        elif nlist.n_type & N_TYPE == N_PBUD:
            return "prebound"
        elif nlist.n_type & N_TYPE == N_INDR:
            return "indirect"
        return "unknown"
    
    def _is_function_symbol(self, nlist) -> bool:
        """Определяет, является ли символ функцией"""
        # Это упрощенная проверка, можно расширить при необходимости
        return nlist.n_type & N_TYPE == N_SECT and nlist.n_value != 0
    
    def _demangle_symbol(self, symbol_name: str) -> str:
        """Демангл C++ символов"""
        # Здесь можно добавить реальный демангл
        # Например, использовать c++filt или подобный инструмент
        return symbol_name
    
    def _print_import_export_info(self, info: Dict[str, Any]) -> None:
        """Выводит информацию об импортах и экспортах"""
        try:
            # Основная информация
            basic_info = info["basic_info"]
            console.print("\n[bold magenta]Основная информация о импортах и экспортах[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Всего библиотек", str(basic_info["total_libraries"])],
                ["Всего импортов", str(basic_info["total_imports"])],
                ["Всего экспортов", str(basic_info["total_exports"])],
                ["Подозрительных импортов", str(basic_info["suspicious_count"])]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Импортируемые библиотеки
            if info["imports"]["libraries"]:
                console.print("\n[bold cyan]Импортируемые библиотеки[/bold cyan]")
                lib_table = Table(show_header=True, header_style="bold cyan")
                lib_table.add_column("Путь", style="cyan")
                lib_table.add_column("Имя", style="yellow")
                lib_table.add_column("Версия", style="green")
                lib_table.add_column("Слабая", style="yellow")
                
                for lib in info["imports"]["libraries"]:
                    version = f"{lib['current_version']} (совместимость: {lib['compatibility_version']})"
                    lib_table.add_row(
                        lib["path"],
                        lib["name"],
                        version,
                        "Да" if lib["weak"] else "Нет"
                    )
                console.print(lib_table)
            
            # Импортируемые символы
            if info["imports"]["symbols"]:
                console.print("\n[bold blue]Импортируемые символы[/bold blue]")
                imp_table = Table(show_header=True, header_style="bold blue")
                imp_table.add_column("Имя", style="cyan")
                imp_table.add_column("Тип", style="yellow")
                imp_table.add_column("Слабая", style="yellow")
                imp_table.add_column("Демангл", style="green")
                
                for sym in info["imports"]["symbols"]:
                    imp_table.add_row(
                        sym["name"],
                        sym["type"],
                        "Да" if sym.get("weak", False) else "Нет",
                        sym.get("demangled", "-")
                    )
                console.print(imp_table)
            
            # Подозрительные импорты
            if info["imports"]["suspicious"]:
                console.print("\n[bold red]Подозрительные импорты[/bold red]")
                sus_table = Table(show_header=True, header_style="bold red")
                sus_table.add_column("Имя", style="cyan")
                sus_table.add_column("Тип", style="yellow")
                
                for sym in info["imports"]["suspicious"]:
                    sus_table.add_row(sym["name"], sym["type"])
                console.print(sus_table)
            
            # Экспортируемые символы
            if info["exports"]["symbols"]:
                console.print("\n[bold yellow]Экспортируемые символы[/bold yellow]")
                exp_table = Table(show_header=True, header_style="bold yellow")
                exp_table.add_column("Имя", style="cyan")
                exp_table.add_column("Тип", style="yellow")
                exp_table.add_column("Адрес", style="green")
                exp_table.add_column("Демангл", style="green")
                
                for sym in info["exports"]["symbols"]:
                    exp_table.add_row(
                        sym["name"],
                        sym["type"],
                        hex(sym["address"]) if sym["address"] else "N/A",
                        sym.get("demangled", "-")
                    )
                console.print(exp_table)
            
            # Динамическая линковка
            if any(info["dynamic_linking"].values()):
                console.print("\n[bold magenta]Динамическая линковка[/bold magenta]")
                dyn_table = Table(show_header=True, header_style="bold magenta")
                dyn_table.add_column("Тип", style="cyan")
                dyn_table.add_column("Количество", style="yellow")
                
                for binding_type, bindings in info["dynamic_linking"].items():
                    if bindings:
                        for binding in bindings:
                            dyn_table.add_row(
                                binding_type.replace("_", " ").title(),
                                str(binding["count"])
                            )
                console.print(dyn_table)
            
            # Оценка рисков
            if info["risk_assessment"]["reasons"]:
                console.print("\n[bold red]Оценка рисков[/bold red]")
                risk_table = Table(show_header=True, header_style="bold red")
                risk_table.add_column("Уровень", style="cyan")
                risk_table.add_column("Причины", style="yellow")
                risk_table.add_column("Рекомендации", style="green")
                
                risk_table.add_row(
                    info["risk_assessment"]["level"],
                    "\n".join(info["risk_assessment"]["reasons"]),
                    "\n".join(info["risk_assessment"]["recommendations"])
                )
                console.print(risk_table)
                
        except Exception as e:
            console.print(f"[red]Ошибка при выводе информации об импортах и экспортах: {str(e)}[/red]")
    
    @staticmethod
    def get_name() -> str:
        return "import_export_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует таблицы импорта и экспорта в Mach-O файлах"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 