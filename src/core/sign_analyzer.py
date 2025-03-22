import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
import re

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
    REVOKED = "Revoked"
    EXPIRED = "Expired"
    UNTRUSTED = "Untrusted"


@dataclass
class SignInfo:
    """Информация о подписи"""
    status: SignStatus
    sign_type: Optional[SignType] = None
    details: Optional[str] = None
    entitlements: Optional[Dict[str, Any]] = None
    team_id: Optional[str] = None
    timestamp: Optional[str] = None
    certificate_chain: Optional[List[Dict[str, str]]] = None
    revocation_status: Optional[Dict[str, Any]] = None
    trust_status: Optional[Dict[str, Any]] = None
    developer_info: Optional[Dict[str, str]] = None
    analyzed_entitlements: Optional[Dict[str, List[Tuple[str, Any]]]] = None


class SignAnalyzer:
    """Анализатор подписи кода Mach-O файлов"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        
    def _run_codesign(self, args: List[str]) -> str:
        """Запуск команды codesign"""
        cmd = ['codesign'] + args
        print(f"Выполняется команда: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout + result.stderr
        
    def _parse_sign_type(self, output: str) -> Optional[SignType]:
        """Определение типа подписи"""
        if "not signed" in output.lower():
            return None
        if "ad-hoc" in output.lower() or "adhoc" in output.lower():
            return SignType.ADHOC
        if "developer id" in output.lower():
            return SignType.DEVELOPER_ID
        if "apple" in output.lower():
            return SignType.APPLE
        return SignType.UNKNOWN
        
    def _verify_signature(self) -> bool:
        """Проверка валидности подписи"""
        result = subprocess.run(['codesign', '--verify', '--verbose=4', self.file_path],
                              capture_output=True, text=True, check=False)
        return result.returncode == 0
        
    def _get_developer_info(self, output: str) -> Optional[Dict[str, str]]:
        """Получение информации о разработчике"""
        info = {}
        
        # Ищем Authority
        authority_pattern = r'Authority=([^\n]+)'
        authorities = re.findall(authority_pattern, output)
        if authorities:
            info['authority'] = authorities[0]
            
        # Ищем TeamIdentifier
        team_pattern = r'TeamIdentifier=([^\n]+)'
        team_match = re.search(team_pattern, output)
        if team_match:
            info['team_id'] = team_match.group(1)
            
        return info if info else None
        
    def _get_timestamp(self, output: str) -> Optional[str]:
        """Получение временной метки подписи"""
        timestamp_pattern = r'Timestamp=([^\n]+)'
        match = re.search(timestamp_pattern, output)
        return match.group(1) if match else None
        
    def _parse_entitlements(self, output: str) -> Optional[Dict[str, Any]]:
        """Парсинг entitlements из вывода codesign"""
        try:
            # Получаем entitlements в формате XML
            cmd = ['codesign', '-d', '--entitlements', ':-', self.file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            stdout = result.stdout
            
            if not stdout or "<?xml" not in stdout:
                return None
                
            # Извлекаем XML часть из вывода
            xml_start = stdout.find('<?xml')
            if xml_start == -1:
                return None
            xml_content = stdout[xml_start:]
            
            # Парсим XML
            root = ET.fromstring(xml_content)
            if root.tag != 'plist' or len(root) == 0:
                return None
                
            # Получаем корневой dict
            dict_elem = root.find('dict')
            if dict_elem is None:
                return None
                
            return self._parse_dict_value(dict_elem)
            
        except ET.ParseError as e:
            print(f"Ошибка парсинга XML: {str(e)}")
            return None
        except ValueError as e:
            print(f"Ошибка преобразования значений: {str(e)}")
            return None
        except Exception as e:
            print(f"Неожиданная ошибка при парсинге entitlements: {str(e)}")
            return None
            
    def _parse_dict_value(self, dict_elem: ET.Element) -> Dict[str, Any]:
        """Парсинг значений из XML элемента dict"""
        result = {}
        key = None
        
        for child in dict_elem:
            if child.tag == 'key':
                key = child.text
            else:
                if key is None:
                    continue
                    
                if child.tag == 'true':
                    value = True
                elif child.tag == 'false':
                    value = False
                elif child.tag == 'integer':
                    value = int(child.text)
                elif child.tag == 'real':
                    value = float(child.text)
                elif child.tag == 'string':
                    value = child.text
                elif child.tag == 'array':
                    value = [self._parse_value(item) for item in child]
                elif child.tag == 'dict':
                    value = self._parse_dict_value(child)
                else:
                    value = None
                    
                result[key] = value
                key = None
                
        return result
        
    def _parse_value(self, elem: ET.Element) -> Any:
        """Парсинг одиночного значения из XML элемента"""
        if elem.tag == 'true':
            return True
        elif elem.tag == 'false':
            return False
        elif elem.tag == 'integer':
            return int(elem.text)
        elif elem.tag == 'real':
            return float(elem.text)
        elif elem.tag == 'string':
            return elem.text
        elif elem.tag == 'array':
            return [self._parse_value(item) for item in elem]
        elif elem.tag == 'dict':
            return self._parse_dict_value(elem)
        return None
        
    def _analyze_entitlements(self, entitlements: Optional[Dict[str, Any]]) -> Dict[str, List[Tuple[str, Any]]]:
        """Анализ entitlements и их группировка по категориям"""
        if not entitlements:
            return {
                'security_sensitive': [],
                'hardware_access': [],
                'data_access': [],
                'network': [],
                'system': [],
                'development': [],
                'other': []
            }
            
        result = {
            'security_sensitive': [],      # Критичные для безопасности разрешения
            'hardware_access': [],         # Доступ к оборудованию
            'data_access': [],            # Доступ к данным
            'network': [],                # Сетевые разрешения
            'system': [],                 # Системные разрешения
            'development': [],            # Разработческие разрешения
            'other': []                   # Прочие разрешения
        }
        
        # Анализируем каждый entitlement
        for key, value in entitlements.items():
            if any(s in key.lower() for s in ['keychain', 'security', 'private']):
                result['security_sensitive'].append((key, value))
            elif any(s in key.lower() for s in ['camera', 'microphone', 'usb', 'device']):
                result['hardware_access'].append((key, value))
            elif any(s in key.lower() for s in ['addressbook', 'calendar', 'location', 'data']):
                result['data_access'].append((key, value))
            elif any(s in key.lower() for s in ['network', 'client']):
                result['network'].append((key, value))
            elif any(s in key.lower() for s in ['system', 'temporary-exception']):
                result['system'].append((key, value))
            elif any(s in key.lower() for s in ['developer', 'debug']):
                result['development'].append((key, value))
            else:
                result['other'].append((key, value))
                
        return result
        
    def analyze(self) -> SignInfo:
        """Анализ подписи файла"""
        try:
            # Получаем основную информацию о подписи
            output = self._run_codesign(['-dvv', self.file_path])
            
            # Проверяем тип подписи
            sign_type = self._parse_sign_type(output)
            if not sign_type:
                return SignInfo(
                    status=SignStatus.UNSIGNED,
                    sign_type=SignType.UNKNOWN,
                    details="File is not signed"
                )
                
            # Проверяем валидность подписи
            is_valid = self._verify_signature()
            status = SignStatus.VALID if is_valid else SignStatus.INVALID
            
            # Получаем информацию о разработчике
            developer_info = self._get_developer_info(output)
            
            # Получаем и анализируем entitlements
            entitlements = self._parse_entitlements(output)
            analyzed_entitlements = self._analyze_entitlements(entitlements)
            
            # Получаем timestamp
            timestamp = self._get_timestamp(output)
            
            return SignInfo(
                status=status,
                sign_type=sign_type,
                details=output,
                developer_info=developer_info,
                entitlements=entitlements,
                analyzed_entitlements=analyzed_entitlements,
                timestamp=timestamp
            )
            
        except Exception as e:
            print(f"Ошибка при анализе подписи: {str(e)}")
            return SignInfo(
                status=SignStatus.ERROR,
                sign_type=SignType.UNKNOWN,
                details=str(e)
            )
