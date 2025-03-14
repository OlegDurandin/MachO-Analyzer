import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any
from pathlib import Path
import sys

class SignType(Enum):
    """Типы подписи кода"""
    ADHOC = "ad-hoc"
    DEVELOPER_ID = "Developer ID"
    APPLE = "Apple"
    UNKNOWN = "Unknown"


class SignStatus(Enum):
    """Статус подписи"""
    VALID = "Valid"
    INVALID = "Invalid"
    NOT_SIGNED = "Not signed"
    ERROR = "Error"


@dataclass
class SignInfo:
    """Информация о подписи кода"""
    status: SignStatus
    sign_type: SignType
    details: str
    entitlements: Optional[Dict[str, Any]] = None
    team_id: Optional[str] = None
    timestamp: Optional[str] = None


class SignAnalyzer:
    """Анализатор подписи кода Mach-O файлов"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        
    def _run_codesign(self, args: List[str]) -> tuple[str, str]:
        """Запуск утилиты codesign с заданными аргументами"""
        try:
            # Добавляем --deep для рекурсивной проверки
            cmd = ['codesign', '--deep'] + args + [self.file_path]
            print(f"Выполняется команда: {' '.join(cmd)}")  # Отладочный вывод
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False  # Не вызываем исключение при ненулевом коде возврата
            )
            
            # Если есть ошибка в stderr, возвращаем её
            if result.stderr:
                return result.stdout, result.stderr
                
            # Если есть вывод в stdout, возвращаем его
            if result.stdout:
                return result.stdout, ""
                
            # Если нет ни stdout, ни stderr, но есть код возврата
            if result.returncode != 0:
                return "", f"codesign завершился с кодом {result.returncode}"
                
            return "", "Не удалось получить вывод от codesign"
            
        except subprocess.CalledProcessError as e:
            return e.stdout, e.stderr
        except Exception as e:
            return "", f"Ошибка при выполнении codesign: {str(e)}"
            
    def _parse_sign_type(self, output: str) -> SignType:
        """Определение типа подписи из вывода codesign"""
        if "ad-hoc" in output.lower() or "adhoc" in output.lower():
            return SignType.ADHOC
        elif "developer id" in output.lower():
            return SignType.DEVELOPER_ID
        elif "apple" in output.lower():
            return SignType.APPLE
        return SignType.UNKNOWN
        
    def _parse_entitlements(self, output: str) -> Optional[Dict[str, Any]]:
        """Парсинг entitlements из вывода codesign"""
        if "entitlements" not in output.lower():
            return None
            
        # Получаем entitlements в формате XML
        stdout, _ = self._run_codesign(['--display', '--xml'])
        if not stdout:
            return None
            
        # TODO: Добавить парсинг XML
        return {}
        
    def analyze(self) -> SignInfo:
        """Анализ подписи кода"""
        # Проверяем наличие подписи и её валидность
        stdout, stderr = self._run_codesign(['-v'])
        
        # Если файл не подписан
        if "not signed" in stderr.lower():
            return SignInfo(
                status=SignStatus.NOT_SIGNED,
                sign_type=SignType.UNKNOWN,
                details="Файл не подписан"
            )
            
        # Получаем детальную информацию о подписи
        details_stdout, details_stderr = self._run_codesign(['-dvv'])
        
        # Если есть ошибки валидации
        if details_stderr and "invalid" in details_stderr.lower():
            return SignInfo(
                status=SignStatus.INVALID,
                sign_type=self._parse_sign_type(details_stdout),
                details=details_stdout.strip()
            )
        else:
            details_stdout = details_stderr
        # Парсим информацию о подписи
        sign_type = self._parse_sign_type(details_stdout)
        entitlements = self._parse_entitlements(details_stdout)
        
        # Извлекаем Team ID и timestamp
        team_id = None
        timestamp = None
        
        for line in details_stdout.split('\n'):
            if "TeamIdentifier" in line:
                team_id = line.split(':')[-1].strip()
            elif "Timestamp" in line:
                timestamp = line.split(':')[-1].strip()
                
        return SignInfo(
            status=SignStatus.VALID,
            sign_type=sign_type,
            details=details_stdout.strip(),
            entitlements=entitlements,
            team_id=team_id,
            timestamp=timestamp
        )
