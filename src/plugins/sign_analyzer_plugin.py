from typing import Dict, Any
from core.plugin_base import MachOPlugin
from core.sign_analyzer import SignAnalyzer, SignInfo, SignType, SignStatus
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class SignAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа подписи Mach-O файла"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.sign_analyzer = SignAnalyzer(file_path)
    
    def analyze(self) -> SignInfo:
        """Анализирует подпись Mach-O файла"""
        return self.sign_analyzer.analyze()
    
    def _print_sign_info(self, sign_info: SignInfo):
        """Выводит информацию о подписи"""
        if not sign_info:
            console.print("\n[bold red]Ошибка: Не удалось получить информацию о подписи[/bold red]")
            return

        # Основная информация о подписи
        console.print("\n[bold green]Информация о подписи[/bold green]")
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Параметр")
        table.add_column("Значение")
        
        # Статус подписи
        status_color = {
            SignStatus.VALID: "green",
            SignStatus.INVALID: "red",
            SignStatus.NOT_SIGNED: "yellow",
            SignStatus.ERROR: "red",
            SignStatus.REVOKED: "red",
            SignStatus.EXPIRED: "red",
            SignStatus.UNTRUSTED: "red"
        }.get(sign_info.status, "white")
        
        table.add_row("Статус", f"[{status_color}]{sign_info.status.value}[/{status_color}]")
        
        # Тип подписи
        if sign_info.sign_type:
            table.add_row("Тип подписи", sign_info.sign_type.value)
        
        # Временная метка
        if sign_info.timestamp:
            table.add_row("Временная метка", sign_info.timestamp)
            
        console.print(table)
        
        # Информация о разработчике
        if sign_info.developer_info:
            console.print("\n[bold blue]Информация о разработчике[/bold blue]")
            dev_table = Table(show_header=True, header_style="bold blue")
            dev_table.add_column("Параметр")
            dev_table.add_column("Значение")
            
            if 'authority' in sign_info.developer_info:
                dev_table.add_row("Authority", sign_info.developer_info['authority'])
            if 'team_id' in sign_info.developer_info:
                dev_table.add_row("Team ID", sign_info.developer_info['team_id'])
                
            console.print(dev_table)
        
        # Entitlements
        if sign_info.analyzed_entitlements:
            console.print("\n[bold yellow]Entitlements[/bold yellow]")
            
            # Группируем entitlements по категориям
            for category, entitlements in sign_info.analyzed_entitlements.items():
                if entitlements:  # Показываем только непустые категории
                    console.print(f"\n[bold]{category.replace('_', ' ').title()}[/bold]")
                    ent_table = Table(show_header=True, header_style="bold")
                    ent_table.add_column("Entitlement")
                    ent_table.add_column("Значение")
                    
                    for key, value in entitlements:
                        ent_table.add_row(key, str(value))
                        
                    console.print(ent_table)
    
    @staticmethod
    def get_name() -> str:
        return "sign_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует подпись Mach-O файла, включая проверку сертификатов и прав"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True 