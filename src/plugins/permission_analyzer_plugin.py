from typing import Dict, Any, List
from macholib.MachO import MachO
from core.plugin_base import MachOPlugin
from core.permission_analyzer import PermissionAnalyzer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.security_analyzer import SeverityLevel
from macholib.mach_o import (
    LC_SEGMENT, LC_SEGMENT_64, MH_MAGIC_64, MH_CIGAM_64,
    LC_CODE_SIGNATURE
)
import re
import subprocess
import json
import os

console = Console()

class PermissionAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа разрешений в Mach-O файле"""
    
    def __init__(self, macho: MachO, file_path: str):
        super().__init__(macho, file_path)
        self.permission_analyzer = PermissionAnalyzer(self.macho, file_path)
        
        # Определяем числовые значения для уровней риска
        self.risk_levels = {
            SeverityLevel.INFO: 0,
            SeverityLevel.WARNING: 1,
            SeverityLevel.CRITICAL: 2
        }
        
        # Критические разрешения
        self.critical_permissions = [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.disable-executable-page-protection",
            "com.apple.security.cs.debugger",
            "com.apple.security.cs.disable-dyld-environment-variables"
        ]
        
        # Подозрительные разрешения
        self.suspicious_permissions = [
            "com.apple.security.network.client",
            "com.apple.security.network.server",
            "com.apple.security.files.user-selected.read-write",
            "com.apple.security.files.downloads.read-write",
            "com.apple.security.files.downloads.read-only",
            "com.apple.security.files.user-selected.read-only"
        ]
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует разрешения в Mach-O файле"""
        results = {
            "basic_info": {
                "total_permissions": 0,
                "critical_count": 0,
                "suspicious_count": 0,
                "risk_level": SeverityLevel.INFO
            },
            "permission_analysis": {
                "entitlements": {},
                "capabilities": {},
                "hardened_runtime": {},
                "sandbox": {}
            },
            "risk_assessment": {
                "level": SeverityLevel.INFO,
                "reasons": [],
                "recommendations": []
            }
        }
        
        # Анализ через codesign и security
        try:
            # Получаем информацию о подписи
            codesign_output = subprocess.check_output(
                ['codesign', '-dvv', self.file_path],
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            
            # Извлекаем entitlements из текстового вывода
            self._extract_entitlements_from_text(codesign_output, results)
                
        except subprocess.CalledProcessError as e:
            console.print(f"[yellow]Предупреждение: Ошибка выполнения codesign: {str(e)}[/yellow]")
            # Пробуем альтернативный метод
            self._extract_entitlements_from_binary(results)
        except Exception as e:
            console.print(f"[yellow]Предупреждение: Не удалось получить entitlements: {str(e)}[/yellow]")
        
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
                                    # Поиск разрешений
                                    self._analyze_permissions(data, results)
                    except Exception as e:
                        console.print(f"[yellow]Предупреждение: Ошибка при чтении сегмента {segname}: {str(e)}[/yellow]")
                        continue
        
        # Оценка рисков
        self._assess_risks(results)
        
        return results
    
    def _extract_entitlements_from_text(self, text: str, results: Dict[str, Any]) -> None:
        """Извлекает entitlements из текстового вывода"""
        try:
            # Ищем блок entitlements
            entitlements_pattern = r'Entitlements:\s*{([^}]+)}'
            entitlements_match = re.search(entitlements_pattern, text, re.DOTALL)
            
            if entitlements_match:
                entitlements_text = entitlements_match.group(1)
                
                # Ищем пары key-value в разных форматах
                patterns = [
                    # Формат "key" = "value"
                    r'"([^"]+)"\s*=\s*"([^"]+)"',
                    # Формат key = value
                    r'([a-zA-Z0-9\.-]+)\s*=\s*"([^"]+)"',
                    # Формат key = true/false
                    r'([a-zA-Z0-9\.-]+)\s*=\s*(true|false)',
                    # Формат key = (value1, value2)
                    r'([a-zA-Z0-9\.-]+)\s*=\s*\(([^)]+)\)'
                ]
                
                for pattern in patterns:
                    for key, value in re.findall(pattern, entitlements_text):
                        # Обрабатываем значение в зависимости от формата
                        if value.startswith('('):
                            # Обработка массива
                            value = [v.strip().strip('"') for v in value.strip('()').split(',')]
                        elif value.lower() in ('true', 'false'):
                            # Обработка булевых значений
                            value = value.lower() == 'true'
                        else:
                            # Обработка строковых значений
                            value = value.strip('"')
                        
                        results["permission_analysis"]["entitlements"][key] = value
                        results["basic_info"]["total_permissions"] += 1
                        
                        if key in self.critical_permissions:
                            results["basic_info"]["critical_count"] += 1
                        elif key in self.suspicious_permissions:
                            results["basic_info"]["suspicious_count"] += 1
        except Exception as e:
            console.print(f"[yellow]Предупреждение: Ошибка при извлечении entitlements из текста: {str(e)}[/yellow]")
    
    def _extract_entitlements_from_binary(self, results: Dict[str, Any]) -> None:
        """Извлекает entitlements напрямую из бинарного файла"""
        try:
            # Ищем секцию с entitlements
            for header in self.macho.headers:
                for cmd in header.commands:
                    if cmd[0].cmd == LC_CODE_SIGNATURE:
                        with open(self.file_path, 'rb') as f:
                            f.seek(cmd[1].dataoff)
                            data = f.read(cmd[1].datasize)
                            # Ищем entitlements в бинарных данных
                            self._find_entitlements_in_binary(data, results)
        except Exception as e:
            console.print(f"[yellow]Предупреждение: Ошибка при извлечении entitlements из бинарного файла: {str(e)}[/yellow]")
    
    def _find_entitlements_in_binary(self, data: bytes, results: Dict[str, Any]) -> None:
        """Ищет entitlements в бинарных данных"""
        try:
            # Ищем строки entitlements
            text = data.decode('utf-8', errors='ignore')
            entitlements_pattern = r'com\.apple\.security\.[a-zA-Z0-9\.-]+'
            for match in re.finditer(entitlements_pattern, text):
                entitlement = match.group(0)
                results["permission_analysis"]["entitlements"][entitlement] = True
                results["basic_info"]["total_permissions"] += 1
                
                if entitlement in self.critical_permissions:
                    results["basic_info"]["critical_count"] += 1
                elif entitlement in self.suspicious_permissions:
                    results["basic_info"]["suspicious_count"] += 1
        except Exception as e:
            console.print(f"[yellow]Предупреждение: Ошибка при поиске entitlements в бинарных данных: {str(e)}[/yellow]")
    
    def _analyze_permissions(self, data: bytes, results: Dict[str, Any]) -> None:
        """Анализирует разрешения в данных"""
        # Поиск capabilities
        capabilities = self._find_capabilities(data)
        for key, value in capabilities.items():
            results["permission_analysis"]["capabilities"][key] = value
            results["basic_info"]["total_permissions"] += 1
        
        # Поиск настроек Hardened Runtime
        hardened = self._find_hardened_runtime(data)
        for key, value in hardened.items():
            results["permission_analysis"]["hardened_runtime"][key] = value
            results["basic_info"]["total_permissions"] += 1
        
        # Поиск настроек Sandbox
        sandbox = self._find_sandbox(data)
        for key, value in sandbox.items():
            results["permission_analysis"]["sandbox"][key] = value
            results["basic_info"]["total_permissions"] += 1
    
    def _find_entitlements(self, data: bytes) -> Dict[str, bool]:
        """Находит entitlements в данных"""
        entitlements = {}
        for permission in self.critical_permissions + self.suspicious_permissions:
            if re.search(permission.encode(), data, re.IGNORECASE):
                entitlements[permission] = True
        return entitlements
    
    def _find_capabilities(self, data: bytes) -> Dict[str, bool]:
        """Находит capabilities в данных"""
        capabilities = {}
        capability_patterns = [
            r"com.apple.security.cs.allow-jit",
            r"com.apple.security.cs.allow-unsigned-executable-memory",
            r"com.apple.security.cs.disable-library-validation"
        ]
        for pattern in capability_patterns:
            if re.search(pattern.encode(), data, re.IGNORECASE):
                capabilities[pattern] = True
        return capabilities
    
    def _find_hardened_runtime(self, data: bytes) -> Dict[str, bool]:
        """Находит настройки Hardened Runtime в данных"""
        hardened = {}
        hardened_patterns = [
            r"com.apple.security.cs.debugger",
            r"com.apple.security.cs.disable-executable-page-protection",
            r"com.apple.security.cs.disable-dyld-environment-variables"
        ]
        for pattern in hardened_patterns:
            if re.search(pattern.encode(), data, re.IGNORECASE):
                hardened[pattern] = True
        return hardened
    
    def _find_sandbox(self, data: bytes) -> Dict[str, bool]:
        """Находит настройки Sandbox в данных"""
        sandbox = {}
        sandbox_patterns = [
            r"com.apple.security.app-sandbox",
            r"com.apple.security.files.user-selected.read-write",
            r"com.apple.security.files.downloads.read-write"
        ]
        for pattern in sandbox_patterns:
            if re.search(pattern.encode(), data, re.IGNORECASE):
                sandbox[pattern] = True
        return sandbox
    
    def _assess_risks(self, results: Dict[str, Any]) -> None:
        """Оценивает риски на основе анализа"""
        risk_level = SeverityLevel.INFO
        reasons = []
        recommendations = []
        
        # Оценка на основе критических разрешений
        if results["basic_info"]["critical_count"] > 0:
            risk_level = SeverityLevel.CRITICAL
            reasons.append(f"Обнаружены критические разрешения ({results['basic_info']['critical_count']})")
            recommendations.append("Требуется детальный анализ разрешений")
            recommendations.append("Рекомендуется отозвать критические разрешения")
        elif results["basic_info"]["suspicious_count"] > 2:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружено значительное количество подозрительных разрешений ({results['basic_info']['suspicious_count']})")
            recommendations.append("Проверить все подозрительные разрешения")
        
        # Оценка на основе общего количества разрешений
        if results["basic_info"]["total_permissions"] > 10:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружено большое количество разрешений ({results['basic_info']['total_permissions']})")
            recommendations.append("Проверить необходимость всех разрешений")
        
        results["risk_assessment"].update({
            "level": risk_level,
            "reasons": reasons,
            "recommendations": recommendations
        })
    
    def _print_permissions_info(self, info: Dict[str, Any]) -> None:
        """Выводит информацию о разрешениях"""
        try:
            # Основная информация
            basic_info = info["basic_info"]
            console.print("\n[bold magenta]Основная информация о разрешениях[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Всего разрешений", str(basic_info["total_permissions"])],
                ["Критических", str(basic_info["critical_count"])],
                ["Подозрительных", str(basic_info["suspicious_count"])],
                ["Уровень риска", str(info["risk_assessment"]["level"])]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Entitlements
            if info["permission_analysis"]["entitlements"]:
                console.print("\n[bold cyan]Entitlements[/bold cyan]")
                entitlements_table = Table(show_header=True, header_style="bold cyan")
                entitlements_table.add_column("Разрешение", style="cyan")
                entitlements_table.add_column("Статус", style="yellow")
                entitlements_table.add_column("Уровень риска", style="red")
                
                for permission, value in info["permission_analysis"]["entitlements"].items():
                    risk_level = "CRITICAL" if permission in self.critical_permissions else "WARNING" if permission in self.suspicious_permissions else "INFO"
                    style = "red" if risk_level == "CRITICAL" else "yellow" if risk_level == "WARNING" else "green"
                    entitlements_table.add_row(
                        permission,
                        "Активно" if value else "Неактивно",
                        f"[{style}]{risk_level}[/{style}]"
                    )
                console.print(entitlements_table)
            
            # Capabilities
            if info["permission_analysis"]["capabilities"]:
                console.print("\n[bold blue]Capabilities[/bold blue]")
                capabilities_table = Table(show_header=True, header_style="bold blue")
                capabilities_table.add_column("Capability", style="cyan")
                capabilities_table.add_column("Статус", style="yellow")
                
                for capability, value in info["permission_analysis"]["capabilities"].items():
                    capabilities_table.add_row(
                        capability,
                        "Активно" if value else "Неактивно"
                    )
                console.print(capabilities_table)
            
            # Hardened Runtime
            if info["permission_analysis"]["hardened_runtime"]:
                console.print("\n[bold green]Hardened Runtime[/bold green]")
                hardened_table = Table(show_header=True, header_style="bold green")
                hardened_table.add_column("Настройка", style="cyan")
                hardened_table.add_column("Статус", style="yellow")
                
                for setting, value in info["permission_analysis"]["hardened_runtime"].items():
                    hardened_table.add_row(
                        setting,
                        "Активно" if value else "Неактивно"
                    )
                console.print(hardened_table)
            
            # Sandbox
            if info["permission_analysis"]["sandbox"]:
                console.print("\n[bold yellow]Sandbox[/bold yellow]")
                sandbox_table = Table(show_header=True, header_style="bold yellow")
                sandbox_table.add_column("Настройка", style="cyan")
                sandbox_table.add_column("Статус", style="yellow")
                
                for setting, value in info["permission_analysis"]["sandbox"].items():
                    sandbox_table.add_row(
                        setting,
                        "Активно" if value else "Неактивно"
                    )
                console.print(sandbox_table)
            
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
            console.print(f"[red]Ошибка при выводе информации о разрешениях: {str(e)}[/red]")
    
    @staticmethod
    def get_name() -> str:
        return "permission_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует разрешения в Mach-O файле"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 
    
    def print_info_panel(self, title: str, content: str) -> None:
        """Выводит информационную панель"""
        console.print(Panel(content, title=title, border_style="blue"))
        console.print()

    def print_table(self, title: str, columns: List[str], rows: List[List[str]], style: str = "bold") -> None:
        """Выводит таблицу с данными"""
        console.print(Table(title=title, show_header=True, header_style=style))
        for col in columns:
            console.print(Table.grid_header(col, style=style))
        for row in rows:
            console.print(Table.grid_row(row, style=style))
        console.print()
    
    def _find_entitlements_in_text(self, text: str, results: Dict[str, Any]) -> None:
        """Альтернативный метод поиска entitlements в тексте"""
        try:
            # Ищем пары key-value в тексте
            import re
            pattern = r'<key>(.*?)</key>\s*<([^>]+)>(.*?)</\2>'
            matches = re.finditer(pattern, text, re.DOTALL)
            
            for match in matches:
                key = match.group(1).strip()
                value_type = match.group(2)
                value = match.group(3).strip()
                
                # Обрабатываем разные типы значений
                if value_type == 'array':
                    values = re.findall(r'<string>(.*?)</string>', value)
                    value = values if values else "[]"
                elif value_type == 'true':
                    value = "True"
                elif value_type == 'false':
                    value = "False"
                
                results["permission_analysis"]["entitlements"][key] = value
                results["basic_info"]["total_permissions"] += 1
                
                if key in self.critical_permissions:
                    results["basic_info"]["critical_count"] += 1
                elif key in self.suspicious_permissions:
                    results["basic_info"]["suspicious_count"] += 1
        except Exception as e:
            console.print(f"[yellow]Предупреждение: Ошибка при поиске entitlements в тексте: {str(e)}[/yellow]")
    