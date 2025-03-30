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

class NetworkAnalyzerPlugin(MachOPlugin):
    """Плагин для анализа сетевой активности в Mach-O файлах"""
    
    def __init__(self, macho, file_path: str):
        super().__init__(macho, file_path)
        self.network_functions = {
            "socket": ["socket", "socketpair", "accept", "bind", "connect", "listen"],
            "dns": ["gethostbyname", "gethostbyaddr", "getaddrinfo", "getnameinfo"],
            "data_transfer": ["send", "sendto", "recv", "recvfrom", "read", "write"],
            "network_io": ["select", "poll", "epoll", "kqueue"],
            "url": ["curl", "NSURL", "CFURL", "URLSession"]
        }
        
        # Определяем числовые значения для уровней риска
        self.risk_levels = {
            SeverityLevel.INFO: 0,
            SeverityLevel.WARNING: 1,
            SeverityLevel.CRITICAL: 2
        }
        
        # Паттерны для поиска сетевых функций
        self.socket_patterns = [
            b"socket",
            b"connect",
            b"bind",
            b"listen",
            b"accept",
            b"send",
            b"recv",
            b"sendto",
            b"recvfrom"
        ]
        
        self.dns_patterns = [
            b"gethostbyname",
            b"getaddrinfo",
            b"getnameinfo",
            b"dns_query",
            b"resolv"
        ]
        
        # Регулярные выражения для поиска URL и портов
        self.url_pattern = re.compile(b'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*')
        self.port_pattern = re.compile(b'(?:port|PORT|Port)\s*[:=]\s*(\d{1,5})')
    
    def analyze(self) -> Dict[str, Any]:
        """Анализирует сетевую активность в файле"""
        results = {
            "basic_info": {
                "total_functions": 0,
                "total_categories": 0,
                "risk_level": SeverityLevel.INFO
            },
            "network_analysis": {
                "functions": {},
                "urls": [],
                "ports": set(),
                "dns_queries": []
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
                                    # Поиск сетевых функций
                                    for category, functions in self.network_functions.items():
                                        found_functions = []
                                        for func in functions:
                                            if self._search_pattern(data, func):
                                                found_functions.append({
                                                    "name": func,
                                                    "description": self._get_function_description(category, func)
                                                })
                                        if found_functions:
                                            results["network_analysis"]["functions"][category] = found_functions
                                            results["basic_info"]["total_functions"] += len(found_functions)
                                            results["basic_info"]["total_categories"] += 1
                                            
                                            # Поиск URL и портов
                                            if category == "url":
                                                urls = self._extract_urls(data)
                                                results["network_analysis"]["urls"].extend(urls)
                                            
                                            # Поиск портов
                                            ports = self._extract_ports(data)
                                            results["network_analysis"]["ports"].update(ports)
                                            
                                            # Поиск DNS запросов
                                            if category == "dns":
                                                dns_queries = self._extract_dns_queries(data)
                                                results["network_analysis"]["dns_queries"].extend(dns_queries)
                    except Exception as e:
                        console.print(f"[yellow]Предупреждение: Ошибка при чтении сегмента {segname}: {str(e)}[/yellow]")
                        continue
        
        # Оценка рисков
        self._assess_risks(results)
        
        return results
    
    def _assess_risks(self, results: Dict[str, Any]) -> None:
        """Оценивает риски на основе анализа"""
        risk_level = SeverityLevel.INFO
        reasons = []
        recommendations = []
        
        # Оценка на основе количества функций
        if results["basic_info"]["total_functions"] > 10:
            risk_level = SeverityLevel.CRITICAL
            reasons.append(f"Обнаружено большое количество сетевых функций ({results['basic_info']['total_functions']})")
            recommendations.append("Требуется детальный анализ сетевой активности")
            recommendations.append("Рекомендуется мониторинг сетевых соединений")
        elif results["basic_info"]["total_functions"] > 5:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружено значительное количество сетевых функций ({results['basic_info']['total_functions']})")
            recommendations.append("Рекомендуется проверка сетевой активности")
        
        # Оценка на основе категорий
        if results["basic_info"]["total_categories"] > 3:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружены функции в нескольких категориях ({results['basic_info']['total_categories']})")
            recommendations.append("Проверить все сетевые категории")
        
        # Специальные проверки
        if results["network_analysis"]["urls"]:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружены URL ({len(results['network_analysis']['urls'])})")
            recommendations.append("Проверить все URL на безопасность")
        
        if results["network_analysis"]["ports"]:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружены порты ({len(results['network_analysis']['ports'])})")
            recommendations.append("Проверить использование портов")
        
        if results["network_analysis"]["dns_queries"]:
            if self.risk_levels[risk_level] < self.risk_levels[SeverityLevel.WARNING]:
                risk_level = SeverityLevel.WARNING
            reasons.append(f"Обнаружены DNS запросы ({len(results['network_analysis']['dns_queries'])})")
            recommendations.append("Проверить DNS запросы")
        
        results["risk_assessment"].update({
            "level": risk_level,
            "reasons": reasons,
            "recommendations": recommendations
        })
    
    def _extract_urls(self, data: bytes) -> List[str]:
        """Извлекает URL из бинарных данных"""
        urls = []
        for match in self.url_pattern.finditer(data):
            try:
                url = match.group(0).decode('utf-8')
                urls.append(url)
            except:
                continue
        return urls
    
    def _extract_ports(self, data: bytes) -> List[int]:
        """Извлекает номера портов из бинарных данных"""
        ports = []
        for match in self.port_pattern.finditer(data):
            try:
                port = int(match.group(1))
                if 1 <= port <= 65535:  # Валидный диапазон портов
                    ports.append(port)
            except:
                continue
        return ports

    def _print_network_info(self, info: Dict[str, Any]) -> None:
        """Выводит информацию о сетевой активности"""
        try:
            # Основная информация
            basic_info = info["basic_info"]
            console.print("\n[bold magenta]Основная информация о сетевой активности[/bold magenta]")
            basic_table = Table(show_header=True, header_style="bold magenta")
            basic_table.add_column("Параметр", style="cyan")
            basic_table.add_column("Значение", style="yellow")
            
            basic_rows = [
                ["Сетевые функции", str(basic_info["total_functions"])],
                ["Сетевые категории", str(basic_info["total_categories"])],
                ["Уровень риска", str(info["risk_assessment"]["level"])]
            ]
            
            for row in basic_rows:
                basic_table.add_row(*row)
            console.print(basic_table)
            
            # Сетевые функции
            if info["network_analysis"]["functions"]:
                console.print("\n[bold cyan]Сетевые функции[/bold cyan]")
                net_table = Table(show_header=True, header_style="bold cyan")
                net_table.add_column("Категория", style="cyan")
                net_table.add_column("Функция", style="cyan")
                net_table.add_column("Описание", style="yellow")
                
                for category, functions in info["network_analysis"]["functions"].items():
                    for func in functions:
                        net_table.add_row(category, func["name"], func["description"])
                console.print(net_table)
            
            # URL
            if info["network_analysis"]["urls"]:
                console.print("\n[bold yellow]Найденные URL[/bold yellow]")
                url_table = Table(show_header=True, header_style="bold yellow")
                url_table.add_column("URL", style="cyan")
                url_table.add_column("Тип", style="yellow")
                
                for url in info["network_analysis"]["urls"]:
                    url_type = "HTTPS" if url.startswith("https://") else "HTTP"
                    url_table.add_row(url, url_type)
                console.print(url_table)
            
            # Порты
            if info["network_analysis"]["ports"]:
                console.print("\n[bold magenta]Найденные порты[/bold magenta]")
                port_table = Table(show_header=True, header_style="bold magenta")
                port_table.add_column("Порт", style="cyan")
                port_table.add_column("Описание", style="yellow")
                
                for port in sorted(info["network_analysis"]["ports"]):
                    port_table.add_row(
                        str(port),
                        self._get_port_description(port)
                    )
                console.print(port_table)
            
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
            console.print(f"[red]Ошибка при выводе информации о сетевой активности: {str(e)}[/red]")

    def _get_function_description(self, category: str, func: str) -> str:
        """Возвращает описание сетевой функции"""
        descriptions = {
            "socket": "Создание сетевого сокета",
            "connect": "Подключение к удаленному хосту",
            "bind": "Привязка сокета к локальному адресу",
            "listen": "Прослушивание входящих соединений",
            "accept": "Принятие входящего соединения",
            "send": "Отправка данных",
            "recv": "Получение данных",
            "sendto": "Отправка данных на указанный адрес",
            "recvfrom": "Получение данных с указанием отправителя",
            "gethostbyname": "Получение IP-адреса по имени хоста",
            "getaddrinfo": "Получение информации об адресе",
            "getnameinfo": "Получение имени хоста по IP-адресу",
            "dns_query": "Выполнение DNS-запроса",
            "resolv": "Разрешение DNS-имен"
        }
        return descriptions.get(func, "Неизвестная функция")

    def _get_port_description(self, port: int) -> str:
        """Возвращает описание порта"""
        common_ports = {
            20: "FTP (данные)",
            21: "FTP (управление)",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP"
        }
        return common_ports.get(port, "Неизвестный порт")
    
    @staticmethod
    def get_name() -> str:
        return "network_analyzer"
    
    @staticmethod
    def get_description() -> str:
        return "Анализирует Mach-O файл на наличие сетевой активности"
    
    @staticmethod
    def get_version() -> str:
        return "1.0.0"
    
    @staticmethod
    def is_compatible() -> bool:
        return True

    def _search_pattern(self, data: bytes, pattern: str) -> bool:
        """Поиск паттерна в данных"""
        try:
            return bool(re.search(pattern.encode(), data, re.IGNORECASE))
        except:
            return False 