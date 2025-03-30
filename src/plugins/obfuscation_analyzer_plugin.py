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
import binascii
import math

console = Console()

class ObfuscationAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа обфускации в Mach-O файлах"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.entropy_threshold = 7.0  # Порог энтропии для определения обфускации
        
        # Определяем числовые значения для уровней риска
        self.risk_levels = {
            SeverityLevel.INFO: 0,
            SeverityLevel.WARNING: 1,
            SeverityLevel.CRITICAL: 2
        }
        
        # Паттерны для анализа
        self.encoded_patterns = [
            r"base64",
            r"hex",
            r"rot13",
            r"xor",
            r"aes",
            r"rc4"
        ]
        
        self.suspicious_patterns = [
            r"cmd",
            r"shell",
            r"exec",
            r"system",
            r"eval",
            r"base64",
            r"hex",
            r"xor",
            r"aes",
            r"rc4"
        ]
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует файл на наличие признаков обфускации"""
        results = {
            "basic_info": {
                "total_sections": 0,
                "total_patterns": 0,
                "risk_level": SeverityLevel.INFO
            },
            "obfuscation_analysis": {
                "entropy": {},
                "strings": {
                    "encoded": [],
                    "suspicious": [],
                    "total_count": 0
                },
                "control_flow": {
                    "indirect_calls": 0,
                    "jump_tables": 0,
                    "is_suspicious": False
                }
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
                                    # Анализ энтропии
                                    entropy = self._calculate_entropy(data)
                                    results["obfuscation_analysis"]["entropy"][segname] = {
                                        "value": entropy,
                                        "is_suspicious": entropy > self.entropy_threshold
                                    }
                                    if entropy > self.entropy_threshold:
                                        results["basic_info"]["total_sections"] += 1
                                    
                                    # Анализ строк
                                    strings = self._extract_strings(data)
                                    results["obfuscation_analysis"]["strings"]["total_count"] += len(strings)
                                    
                                    # Поиск закодированных строк
                                    for pattern in self.encoded_patterns:
                                        if re.search(pattern.encode(), data, re.IGNORECASE):
                                            results["obfuscation_analysis"]["strings"]["encoded"].append(pattern)
                                            results["basic_info"]["total_patterns"] += 1
                                    
                                    # Анализ подозрительных строк
                                    for string in strings:
                                        if self._is_suspicious_string(string):
                                            results["obfuscation_analysis"]["strings"]["suspicious"].append(string)
                                            results["basic_info"]["total_patterns"] += 1
                                    
                                    # Анализ потока управления
                                    if segname == '__TEXT':
                                        results["obfuscation_analysis"]["control_flow"]["indirect_calls"] += data.count(b"\xff\xd0")
                                        results["obfuscation_analysis"]["control_flow"]["indirect_calls"] += data.count(b"\xff\xe0")
                                        results["obfuscation_analysis"]["control_flow"]["jump_tables"] += data.count(b"\xff\x24\xc5")
                    except Exception as e:
                        console.print(f"[yellow]Предупреждение: Ошибка при чтении сегмента {segname}: {str(e)}[/yellow]")
                        continue
        
        # Определение подозрительного потока управления
        results["obfuscation_analysis"]["control_flow"]["is_suspicious"] = (
            results["obfuscation_analysis"]["control_flow"]["indirect_calls"] > 10 or
            results["obfuscation_analysis"]["control_flow"]["jump_tables"] > 5
        )
        
        # Оценка рисков
        self._assess_risks(results)
        
        return results
    
    def _assess_risks(self, results: Dict[str, Any]) -> None:
        """Оценивает риски на основе анализа"""
        risk_level = SeverityLevel.INFO
        reasons = []
        recommendations = []
        
        # Оценка на основе энтропии
        if results["basic_info"]["total_sections"] > 2:
            risk_level = SeverityLevel.CRITICAL
            reasons.append(f"Обнаружено большое количество секций с высокой энтропией ({results['basic_info']['total_sections']})")
            recommendations.append("Требуется детальный анализ обфускации")
            recommendations.append("Рекомендуется проверка на наличие упакованного кода")
        elif results["basic_info"]["total_sections"] > 1:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружены секции с высокой энтропией ({results['basic_info']['total_sections']})")
            recommendations.append("Рекомендуется проверка на обфускацию")
        
        # Оценка на основе паттернов
        if results["basic_info"]["total_patterns"] > 5:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружено значительное количество подозрительных паттернов ({results['basic_info']['total_patterns']})")
            recommendations.append("Проверить все подозрительные паттерны")
        
        # Оценка на основе потока управления
        if results["obfuscation_analysis"]["control_flow"]["is_suspicious"]:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append("Обнаружен подозрительный поток управления")
            recommendations.append("Проверить косвенные вызовы и таблицы переходов")
        
        results["risk_assessment"].update({
            "level": risk_level,
            "reasons": reasons,
            "recommendations": recommendations
        })
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Вычисляет энтропию данных"""
        if not data:
            return 0.0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
    
    def _extract_strings(self, data: bytes) -> List[str]:
        """Извлекает строки из бинарных данных"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Печатаемые ASCII символы
                current_string += chr(byte)
            elif current_string:
                if len(current_string) >= 4:  # Минимальная длина строки
                    strings.append(current_string)
                current_string = ""
        
        if current_string and len(current_string) >= 4:
            strings.append(current_string)
        
        return strings
    
    def _is_suspicious_string(self, string: str) -> bool:
        """Проверяет строку на подозрительность"""
        return any(re.search(pattern, string, re.IGNORECASE) for pattern in self.suspicious_patterns)
    
    def _print_obfuscation_info(self, info: Dict[str, Any]) -> None:
        """Выводит информацию об обфускации"""
        try:
            # Основная информация
            basic_info = info["basic_info"]
            console.print("\n[bold magenta]Основная информация о обфускации и энтропии[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Секций с высокой энтропией", str(basic_info["total_sections"])],
                ["Подозрительных паттернов", str(basic_info["total_patterns"])],
                ["Уровень риска", str(info["risk_assessment"]["level"])]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Анализ энтропии
            if info["obfuscation_analysis"]["entropy"]:
                console.print("\n[bold cyan]Анализ энтропии[/bold cyan]")
                entropy_table = Table(show_header=True, header_style="bold cyan")
                entropy_table.add_column("Сегмент", style="cyan")
                entropy_table.add_column("Энтропия", style="yellow")
                entropy_table.add_column("Статус", style="red")
                
                for section, data in info["obfuscation_analysis"]["entropy"].items():
                    status = "Подозрительно" if data["is_suspicious"] else "Нормально"
                    style = "red" if data["is_suspicious"] else "green"
                    entropy_table.add_row(
                        section,
                        f"{data['value']:.2f}",
                        f"[{style}]{status}[/{style}]"
                    )
                console.print(entropy_table)
            
            # Анализ строк
            if info["obfuscation_analysis"]["strings"]:
                console.print("\n[bold blue]Анализ строк[/bold blue]")
                string_table = Table(show_header=True, header_style="bold blue")
                string_table.add_column("Тип", style="cyan")
                string_table.add_column("Количество", style="yellow")
                string_table.add_column("Детали", style="green")
                
                # Закодированные строки
                if info["obfuscation_analysis"]["strings"]["encoded"]:
                    string_table.add_row(
                        "Закодированные строки",
                        str(len(info["obfuscation_analysis"]["strings"]["encoded"])),
                        ", ".join(info["obfuscation_analysis"]["strings"]["encoded"])
                    )
                
                # Подозрительные паттерны
                if info["obfuscation_analysis"]["strings"]["suspicious"]:
                    string_table.add_row(
                        "Подозрительные паттерны",
                        str(len(info["obfuscation_analysis"]["strings"]["suspicious"])),
                        ", ".join(info["obfuscation_analysis"]["strings"]["suspicious"])
                    )
                
                # Общее количество строк
                string_table.add_row(
                    "Всего строк",
                    str(info["obfuscation_analysis"]["strings"]["total_count"]),
                    ""
                )
                console.print(string_table)
            
            # Анализ потока управления
            if info["obfuscation_analysis"]["control_flow"]:
                console.print("\n[bold magenta]Анализ потока управления[/bold magenta]")
                control_table = Table(show_header=True, header_style="bold magenta")
                control_table.add_column("Параметр", style="cyan")
                control_table.add_column("Значение", style="yellow")
                control_table.add_column("Статус", style="red")
                
                # Косвенные вызовы
                status = "Подозрительно" if info["obfuscation_analysis"]["control_flow"]["indirect_calls"] > 10 else "Нормально"
                style = "red" if info["obfuscation_analysis"]["control_flow"]["indirect_calls"] > 10 else "green"
                control_table.add_row(
                    "Косвенные вызовы",
                    str(info["obfuscation_analysis"]["control_flow"]["indirect_calls"]),
                    f"[{style}]{status}[/{style}]"
                )
                
                # Таблицы переходов
                status = "Подозрительно" if info["obfuscation_analysis"]["control_flow"]["jump_tables"] > 5 else "Нормально"
                style = "red" if info["obfuscation_analysis"]["control_flow"]["jump_tables"] > 5 else "green"
                control_table.add_row(
                    "Таблицы переходов",
                    str(info["obfuscation_analysis"]["control_flow"]["jump_tables"]),
                    f"[{style}]{status}[/{style}]"
                )
                
                # Общий статус потока управления
                status = "Подозрительно" if info["obfuscation_analysis"]["control_flow"]["is_suspicious"] else "Нормально"
                style = "red" if info["obfuscation_analysis"]["control_flow"]["is_suspicious"] else "green"
                control_table.add_row(
                    "Общий статус",
                    "",
                    f"[{style}]{status}[/{style}]"
                )
                console.print(control_table)
            
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
            console.print(f"[red]Ошибка при выводе информации об обфускации: {str(e)}[/red]")
    
    @staticmethod
    def get_name() -> str:
        return "obfuscation_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует Mach-O файл на наличие признаков обфускации кода"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 