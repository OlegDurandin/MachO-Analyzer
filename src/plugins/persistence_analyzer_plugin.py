from typing import Dict, Any, List
from core.plugin_base import MachOPlugin
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.security_analyzer import SeverityLevel
from macholib.mach_o import (
    LC_SEGMENT, LC_SEGMENT_64, MH_MAGIC_64, MH_CIGAM_64
)
import re

console = Console()

class PersistenceAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа механизмов персистентности в Mach-O файлах"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        
        # Определяем числовые значения для уровней риска
        self.risk_levels = {
            SeverityLevel.INFO: 0,
            SeverityLevel.WARNING: 1,
            SeverityLevel.CRITICAL: 2
        }
        
        # Паттерны для поиска механизмов персистентности
        self.persistence_patterns = {
            "launch_agents": [
                b"~/Library/LaunchAgents/",
                b"/Library/LaunchAgents/",
                b"com.apple.launchd",
                b"launchctl",
                b"LaunchAgent",
                b"LaunchDaemon"
            ],
            "login_items": [
                b"LSSharedFileList",
                b"LSSharedFileListCreate",
                b"LSSharedFileListInsertItemURL",
                b"loginwindow.app",
                b"System/Library/CoreServices/loginwindow.app"
            ],
            "cron_jobs": [
                b"crontab",
                b"/etc/crontab",
                b"/var/at/tabs/",
                b"atrun",
                b"atd"
            ],
            "system_extensions": [
                b"systemextensions",
                b"systemextension",
                b"com.apple.system-extension-install",
                b"systemextensionsctl"
            ],
            "kernel_extensions": [
                b"kext",
                b"kextload",
                b"kextutil",
                b"com.apple.kext",
                b"KextManager"
            ],
            "startup_scripts": [
                b"/etc/rc",
                b"/etc/rc.local",
                b"/etc/rc.d/",
                b"rc.d",
                b"rc.local"
            ],
            "plist_modification": [
                b"CFPreferences",
                b"NSUserDefaults",
                b"defaults write",
                b"plutil",
                b"PropertyList"
            ],
            "file_associations": [
                b"LSHandler",
                b"CFBundleDocumentTypes",
                b"LSItemContentTypes",
                b"UTType"
            ]
        }
        
        # Паттерны для поиска подозрительных системных вызовов
        self.suspicious_syscalls = [
            b"chmod",
            b"chown",
            b"setuid",
            b"setgid",
            b"seteuid",
            b"setegid",
            b"setreuid",
            b"setregid",
            b"setfsuid",
            b"setfsgid",
            b"setresuid",
            b"setresgid"
        ]
        
        # Веса для оценки рисков механизмов
        self.mechanism_weights = {
            "launch_agents": 3,
            "login_items": 2,
            "cron_jobs": 2,
            "system_extensions": 4,
            "kernel_extensions": 5,
            "startup_scripts": 3,
            "plist_modification": 2,
            "file_associations": 2
        }
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует файл на наличие механизмов персистентности"""
        results = {
            "basic_info": {
                "total_mechanisms": 0,
                "total_patterns": 0,
                "suspicious_syscalls_count": 0,
                "risk_score": 0,
                "risk_level": SeverityLevel.INFO
            },
            "persistence_analysis": {
                "mechanisms": {},
                "suspicious_syscalls": [],
                "technical_details": {}
            },
            "risk_assessment": {
                "level": SeverityLevel.INFO,
                "reasons": [],
                "recommendations": []
            }
        }
        
        # Анализ сегментов
        for header in self.macho.headers:
            for cmd in header.commands:
                if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    segment = cmd[1]
                    try:
                        segname = segment.segname.decode('utf-8').strip('\x00')
                        if segname in ['__TEXT', '__DATA']:
                            with open(self.file_path, 'rb') as f:
                                f.seek(segment.fileoff)
                                data = f.read(segment.filesize)
                                if data:
                                    # Поиск механизмов персистентности
                                    self._analyze_persistence(data, results)
                    except Exception as e:
                        console.print(f"[yellow]Предупреждение: Ошибка при чтении сегмента {segname}: {str(e)}[/yellow]")
                        continue
        
        # Оценка рисков
        self._assess_risks(results)
        
        return results
    
    def _analyze_persistence(self, data: bytes, results: Dict[str, Any]) -> None:
        """Анализирует механизмы персистентности в данных"""
        # Поиск механизмов персистентности
        for mechanism, patterns in self.persistence_patterns.items():
            found_patterns = []
            for pattern in patterns:
                if pattern in data:
                    found_patterns.append(pattern.decode('utf-8'))
            if found_patterns:
                results["persistence_analysis"]["mechanisms"][mechanism] = found_patterns
                results["basic_info"]["total_mechanisms"] += 1
                results["basic_info"]["total_patterns"] += len(found_patterns)
        
        # Поиск подозрительных системных вызовов
        for syscall in self.suspicious_syscalls:
            if syscall in data:
                results["persistence_analysis"]["suspicious_syscalls"].append(syscall.decode('utf-8'))
                results["basic_info"]["suspicious_syscalls_count"] += 1
    
    def _assess_risks(self, results: Dict[str, Any]) -> None:
        """Оценивает риски на основе анализа"""
        risk_level = SeverityLevel.INFO
        reasons = []
        recommendations = []
        risk_score = 0
        
        # Оценка механизмов персистентности
        for mechanism, patterns in results["persistence_analysis"]["mechanisms"].items():
            if mechanism in self.mechanism_weights:
                risk_score += len(patterns) * self.mechanism_weights[mechanism]
        
        # Оценка подозрительных системных вызовов
        risk_score += results["basic_info"]["suspicious_syscalls_count"] * 2
        
        # Определение уровня риска
        if risk_score >= 15:
            risk_level = SeverityLevel.CRITICAL
            reasons.append(f"Высокий риск персистентности (score: {risk_score})")
            recommendations.extend([
                "Требуется немедленное удаление вредоносного ПО",
                "Проверить все механизмы автозапуска",
                "Проверить целостность системных файлов",
                "Проверить права доступа к системным директориям",
                "Рассмотреть возможность переустановки системы"
            ])
        elif risk_score >= 8:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Средний риск персистентности (score: {risk_score})")
            recommendations.extend([
                "Проверить все механизмы автозапуска",
                "Проверить права доступа к системным директориям",
                "Мониторить подозрительную активность"
            ])
        else:
            recommendations.append("Базовый мониторинг системной активности")
        
        # Обновление результатов
        results["basic_info"]["risk_score"] = risk_score
        results["basic_info"]["risk_level"] = risk_level
        results["risk_assessment"].update({
            "level": risk_level,
            "reasons": reasons,
            "recommendations": recommendations
        })
    
    def _print_persistence_info(self, info: Dict[str, Any]) -> None:
        """Выводит информацию о механизмах персистентности"""
        try:
            # Основная информация
            basic_info = info["basic_info"]
            console.print("\n[bold magenta]Основная информация о механизмах персистентности[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Всего механизмов", str(basic_info["total_mechanisms"])],
                ["Всего паттернов", str(basic_info["total_patterns"])],
                ["Подозрительных вызовов", str(basic_info["suspicious_syscalls_count"])],
                ["Уровень риска", str(info["risk_assessment"]["level"])],
                ["Оценка риска", str(basic_info["risk_score"])]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Механизмы персистентности
            if info["persistence_analysis"]["mechanisms"]:
                console.print("\n[bold cyan]Механизмы персистентности[/bold cyan]")
                mech_table = Table(show_header=True, header_style="bold cyan")
                mech_table.add_column("Тип", style="cyan")
                mech_table.add_column("Количество", style="yellow")
                mech_table.add_column("Детали", style="green")
                
                for mechanism, patterns in info["persistence_analysis"]["mechanisms"].items():
                    mech_table.add_row(
                        mechanism.replace("_", " ").title(),
                        str(len(patterns)),
                        ", ".join(patterns)
                    )
                console.print(mech_table)
            
            # Подозрительные системные вызовы
            if info["persistence_analysis"]["suspicious_syscalls"]:
                console.print("\n[bold yellow]Подозрительные системные вызовы[/bold yellow]")
                syscall_table = Table(show_header=True, header_style="bold yellow")
                syscall_table.add_column("Системный вызов", style="red")
                syscall_table.add_column("Описание", style="yellow")
                
                for syscall in info["persistence_analysis"]["suspicious_syscalls"]:
                    description = self._get_syscall_description(syscall)
                    syscall_table.add_row(syscall, description)
                console.print(syscall_table)
            
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
            console.print(f"[red]Ошибка при выводе информации о персистентности: {str(e)}[/red]")
    
    def _get_syscall_description(self, syscall: str) -> str:
        """Возвращает описание системного вызова"""
        descriptions = {
            "chmod": "Изменение прав доступа к файлу",
            "chown": "Изменение владельца файла",
            "setuid": "Установка эффективного UID процесса",
            "setgid": "Установка эффективного GID процесса",
            "seteuid": "Установка эффективного UID процесса",
            "setegid": "Установка эффективного GID процесса",
            "setreuid": "Установка реального и эффективного UID",
            "setregid": "Установка реального и эффективного GID",
            "setfsuid": "Установка UID файловой системы",
            "setfsgid": "Установка GID файловой системы",
            "setresuid": "Установка реального, эффективного и сохраненного UID",
            "setresgid": "Установка реального, эффективного и сохраненного GID"
        }
        return descriptions.get(syscall, "Неизвестный системный вызов")
    
    @staticmethod
    def get_name() -> str:
        return "persistence_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует Mach-O файл на наличие механизмов персистентности в macOS"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 