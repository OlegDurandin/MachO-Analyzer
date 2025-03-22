from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Tuple, Union
from macholib.mach_o import *
import struct
import re
import json
import xml.etree.ElementTree as ET
import math
import base64
from pathlib import Path


class DataType(Enum):
    """Типы встроенных данных"""
    STRING = "String"
    IMAGE = "Image"
    SCRIPT = "Script"
    CONFIG = "Config"
    BINARY = "Binary"
    ENCRYPTED = "Encrypted"
    UNKNOWN = "Unknown"


@dataclass
class EmbeddedData:
    """Информация о встроенных данных"""
    type: DataType
    section: str
    offset: int
    size: int
    content: Optional[bytes] = None
    details: Optional[str] = None
    is_sensitive: bool = False

    def __init__(self, section: str, offset: int, size: int, data_type: str, content: Union[str, bytes]):
        """Инициализация объекта встроенных данных"""
        self.section = section
        self.offset = offset
        self.size = size
        self.data_type = data_type
        self.content = content
        self.details = None
        self.is_sensitive = False

    def __str__(self):
        return f"{self.data_type} in section {self.section} at offset {self.offset} (size: {self.size})"

    def __repr__(self):
        return self.__str__()


class EmbeddedDataAnalyzer:
    """Анализатор встроенных данных в Mach-O файлах"""
    
    def __init__(self, macho_file, file_path: str):
        self.macho = macho_file
        self.file_path = file_path
        self.chunk_size = 1024 * 1024  # Читаем по 1MB за раз
        
        # Сигнатуры файлов
        self.signatures = {
            'PNG': b'\x89PNG\r\n\x1a\n',
            'JPEG': b'\xff\xd8\xff',
            'GIF': b'GIF87a',
            'GIF89a': b'GIF89a',
            'PDF': b'%PDF',
            'ZIP': b'PK\x03\x04',
            'RAR': b'Rar!\x1a\x07',
            '7ZIP': b'7z\xbc\xaf\x27\x1c',
            'ELF': b'\x7fELF',
            'MACHO': b'\xfe\xed\xfa\xce',
            'MACHO64': b'\xfe\xed\xfa\xcf',
            'WEBP': b'RIFF',  # Полная сигнатура проверяется отдельно
            'BMP': b'BM',
            'ISO': b'\x01CD001',
            'GZIP': b'\x1f\x8b\x08',
            'BZIP2': b'BZh',
            'DMG': b'koly\x00\x00\x00\x04',
            'DYLIB': b'\xca\xfe\xba\xbe',  # Universal binary
            'TIFF': b'\x49\x49\x2A\x00',   # Little-endian TIFF
            'TIFF_BE': b'\x4D\x4D\x00\x2A' # Big-endian TIFF
        }
        
        # Криптографические константы
        self.crypto_constants = {
            'AES_SBOX': bytes.fromhex('637c777bf26b6fc53001672bfed7ab76'),
            'SHA256_IV': bytes.fromhex('6a09e667bb67ae853c6ef372a54ff53a'),
            'MD5_IV': bytes.fromhex('67452301efcdab8998badcfe10325476'),
            'RSA_E': b'\x01\x00\x01',  # Популярная RSA экспонента (65537)
            'BLOWFISH_PI': bytes.fromhex('243f6a8885a308d313198a2e03707344'),
            'RC4_INIT': bytes([i for i in range(256)][:16]),  # Начало таблицы RC4
            'SERPENT_PHI': bytes.fromhex('9e3779b9'),  # Золотое сечение
            'TWOFISH_RS': bytes.fromhex('01020408102040801b366cd8ab4d9a2f'),
            'CAMELLIA_SIGMA': bytes.fromhex('a09e667f3bcc908b')
        }
        
        # Паттерны для поиска
        self.patterns = {
            'url': rb'https?://[^\s<>"]+|www\.[^\s<>"]+',
            'email': rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ip': rb'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'base64': rb'[A-Za-z0-9+/=]{40,}',
            'api_key': rb'[a-zA-Z0-9_-]{32,}',
            'password': rb'password[\s=:]+[^\s<>"]+',
            'token': rb'token[\s=:]+[^\s<>"]+',
            'key': rb'key[\s=:]+[^\s<>"]+',
            'secret': rb'secret[\s=:]+[^\s<>"]+',
            'javascript': rb'function\s+\w+\s*\([^)]*\)\s*{',
            'python': rb'def\s+\w+\s*\([^)]*\):',
            'lua': rb'function\s+\w+\s*\([^)]*\)',
            'json': rb'\{[\s\S]*\}',
            'xml': rb'<[^>]+>[\s\S]*</[^>]+>',
            'yaml': rb'[a-zA-Z0-9_]+:[\s\S]*?[a-zA-Z0-9_]+:',
            'plist': rb'<\?xml[\s\S]*?<plist[\s\S]*?</plist>'
        }
        
        # Чувствительные паттерны
        self.sensitive_patterns = {
            'password': r'(?i)(password|passwd|pwd|secret|key)[\s]*[=:]\s*\S+',
            'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'file_path': r'(?i)(?:/[\w.-]+)+\.\w+',
            'api_key': r'(?i)(api[_-]?key|token|secret)[^\n]{0,20}[\'"][0-9a-zA-Z]{16,}[\'"]'
        }
        
    def _calculate_entropy(self, data: bytes) -> float:
        """Вычисление энтропии для определения сжатых/зашифрованных данных"""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
        
    def _is_valid_json(self, data: bytes) -> bool:
        """Проверка валидности JSON"""
        try:
            json.loads(data.decode('utf-8'))
            return True
        except:
            return False
            
    def _is_valid_xml(self, data: bytes) -> bool:
        """Проверка валидности XML"""
        try:
            ET.fromstring(data)
            return True
        except:
            return False
            
    def _is_valid_base64(self, data: bytes) -> bool:
        """Проверка валидности Base64"""
        try:
            # Проверяем, что строка содержит только допустимые символы
            if not re.match(rb'^[A-Za-z0-9+/=]+$', data):
                return False
            # Пробуем декодировать
            base64.b64decode(data)
            return True
        except:
            return False
            
    def _detect_data_type(self, data: bytes) -> Tuple[DataType, Optional[str]]:
        """Определение типа данных"""
        # Проверяем криптографические константы
        for const_name, const_value in self.crypto_constants.items():
            if const_value in data:
                return DataType.BINARY, f"Cryptographic constant ({const_name})"
        
        # Проверяем сигнатуры файлов
        for file_type, signature in self.signatures.items():
            if data.startswith(signature):
                # Специальная проверка для WEBP
                if file_type == 'WEBP':
                    if len(data) >= 12 and data[8:12] == b'WEBP':
                        return DataType.IMAGE, f"Image (WEBP)"
                    continue
                    
                if file_type in ('PNG', 'JPEG', 'GIF', 'GIF89a', 'WEBP', 'BMP', 'TIFF', 'TIFF_BE'):
                    return DataType.IMAGE, f"Image ({file_type})"
                elif file_type in ('ZIP', 'RAR', '7ZIP', 'GZIP', 'BZIP2', 'DMG'):
                    return DataType.BINARY, f"Archive ({file_type})"
                elif file_type == 'PDF':
                    return DataType.BINARY, "PDF document"
                elif file_type in ('ELF', 'MACHO', 'MACHO64', 'DYLIB'):
                    return DataType.BINARY, f"Executable ({file_type})"
                    
        # Проверяем энтропию для определения сжатых/зашифрованных данных
        entropy = self._calculate_entropy(data)
        if entropy > 7.0:  # Высокая энтропия может указывать на шифрование
            return DataType.ENCRYPTED, f"Encrypted/Compressed (entropy: {entropy:.2f})"
            
        # Проверяем JSON
        if self._is_valid_json(data):
            return DataType.CONFIG, "JSON configuration"
            
        # Проверяем XML
        if self._is_valid_xml(data):
            return DataType.CONFIG, "XML configuration"
            
        # Проверяем Base64
        if self._is_valid_base64(data):
            return DataType.BINARY, "Base64 encoded data"
            
        # Проверяем скрипты
        for script_type, pattern in self.patterns.items():
            if script_type in ('javascript', 'python', 'lua'):
                if re.search(pattern, data):
                    return DataType.SCRIPT, f"{script_type.capitalize()} script"
                    
        # Проверяем конфигурации
        for config_type, pattern in self.patterns.items():
            if config_type in ('json', 'xml', 'yaml', 'plist'):
                if re.search(pattern, data):
                    return DataType.CONFIG, f"{config_type.upper()} configuration"
                    
        # Если не удалось определить тип
        return DataType.UNKNOWN, None
        
    def _check_sensitive_data(self, data: bytes) -> Tuple[bool, List[str]]:
        """Проверка на наличие чувствительных данных"""
        sensitive_found = []
        is_sensitive = False
        
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = re.finditer(pattern, data, re.IGNORECASE)
            for match in matches:
                is_sensitive = True
                # Маскируем чувствительные данные
                masked_value = match.group(0).decode('utf-8', errors='ignore')
                if ':' in masked_value or '=' in masked_value:
                    key, value = masked_value.split(':', 1) if ':' in masked_value else masked_value.split('=', 1)
                    masked_value = f"{key}: {'*' * len(value.strip())}"
                sensitive_found.append(f"{pattern_name}: {masked_value}")
                
        return is_sensitive, sensitive_found
        
    def _analyze_strings(self, data: bytes) -> List[Tuple[str, int]]:
        """Улучшенный анализ строк"""
        strings = []
        # ASCII строки (минимум 4 символа)
        ascii_pattern = re.compile(b'[ -~]{4,}')
        # UTF-16 строки
        utf16_pattern = re.compile(b'(?:[\x00][ -~]){4,}')
        
        # Поиск ASCII строк
        for match in ascii_pattern.finditer(data):
            try:
                decoded = match.group().decode('ascii')
                if not decoded.isspace():  # Пропускаем строки только из пробелов
                    strings.append((decoded, match.start()))
            except UnicodeDecodeError:
                continue
            
        # Поиск UTF-16 строк
        for match in utf16_pattern.finditer(data):
            try:
                decoded = match.group().decode('utf-16')
                if not decoded.isspace():  # Пропускаем строки только из пробелов
                    strings.append((decoded, match.start()))
            except UnicodeDecodeError:
                continue
            
        return strings

    def _analyze_sensitive_data(self, data: bytes, offset: int) -> List[Tuple[str, int, str]]:
        """
        Анализирует данные на наличие чувствительной информации.
        
        Args:
            data: Бинарные данные для анализа
            offset: Смещение данных в файле
            
        Returns:
            Список кортежей (тип_данных, смещение, найденная_строка)
        """
        results = []
        
        # Пробуем разные кодировки
        encodings = ['utf-8', 'ascii', 'utf-16']
        
        for encoding in encodings:
            try:
                # Декодируем данные
                text = data.decode(encoding, errors='ignore')
                
                # Проверяем каждый шаблон
                for pattern_name, pattern in self.sensitive_patterns.items():
                    try:
                        matches = re.finditer(pattern, text)
                        for match in matches:
                            start = match.start()
                            found_text = match.group()
                            
                            # Пропускаем слишком короткие совпадения
                            if len(found_text) < 4:
                                continue
                                
                            # Вычисляем реальное смещение в файле
                            real_offset = offset + start
                            
                            # Добавляем найденное совпадение
                            results.append((pattern_name, real_offset, found_text))
                    except re.error:
                        continue
                        
            except UnicodeDecodeError:
                continue
                
        return results

    def _analyze_cstring_section(self, section_data: bytes, section_name: str) -> List[EmbeddedData]:
        results = []
        
        # Разделяем данные по нулевым байтам
        strings = section_data.split(b'\x00')
        
        for string in strings:
            if len(string) < 4:  # Пропускаем слишком короткие строки
                continue
            
            try:
                decoded = string.decode('utf-8')
                
                # Проверяем различные паттерны
                if any(pattern in decoded.lower() for pattern in ['password', 'secret', 'key', 'token', 'credential']):
                    results.append(EmbeddedData(
                        section=section_name,
                        offset=section_data.find(string),
                        size=len(string),
                        data_type='Sensitive_string',
                        content=decoded
                    ))
                elif re.search(r'[A-Za-z0-9+/]{32,}={0,2}', decoded):  # Base64
                    results.append(EmbeddedData(
                        section=section_name,
                        offset=section_data.find(string),
                        size=len(string),
                        data_type='Encoded_data',
                        content=decoded
                    ))
                elif re.search(r'[A-Fa-f0-9]{32,}', decoded):  # Hex string
                    results.append(EmbeddedData(
                        section=section_name,
                        offset=section_data.find(string),
                        size=len(string),
                        data_type='Hex_data',
                        content=decoded
                    ))
            except UnicodeDecodeError:
                continue
            
        return results

    def _analyze_objc_section(self, section_data: bytes, section_name: str) -> List[EmbeddedData]:
        results = []
        
        # Разделяем данные по нулевым байтам
        strings = section_data.split(b'\x00')
        
        for string in strings:
            if len(string) < 4:  # Пропускаем слишком короткие строки
                continue
            
            try:
                decoded = string.decode('utf-8')
                
                # Определяем тип строки на основе секции
                if section_name == '__objc_methname':
                    # Анализируем методы на предмет чувствительных операций
                    if any(pattern in decoded.lower() for pattern in ['password', 'key', 'token', 'auth', 'crypt', 'sign']):
                        results.append(EmbeddedData(
                            section=section_name,
                            offset=section_data.find(string),
                            size=len(string),
                            data_type='Sensitive_method',
                            content=decoded
                        ))
                    elif any(pattern in decoded.lower() for pattern in ['init', 'alloc', 'new', 'copy']):
                        results.append(EmbeddedData(
                            section=section_name,
                            offset=section_data.find(string),
                            size=len(string),
                            data_type='Memory_method',
                            content=decoded
                        ))
                    else:
                        results.append(EmbeddedData(
                            section=section_name,
                            offset=section_data.find(string),
                            size=len(string),
                            data_type='ObjC_method',
                            content=decoded
                        ))
                elif section_name == '__objc_classname':
                    # Анализируем имена классов
                    if any(pattern in decoded for pattern in ['Controller', 'Manager', 'Service']):
                        results.append(EmbeddedData(
                            section=section_name,
                            offset=section_data.find(string),
                            size=len(string),
                            data_type='Controller_class',
                            content=decoded
                        ))
                    else:
                        results.append(EmbeddedData(
                            section=section_name,
                            offset=section_data.find(string),
                            data_type='ObjC_class',
                            size=len(string),
                            content=decoded
                        ))
            except UnicodeDecodeError:
                continue
            
        return results

    def get_section_data(self, header, sect) -> bytes:
        """Получение данных секции"""
        try:
            # Если у секции есть метод get_content, используем его
            if hasattr(sect, 'get_content'):
                return sect.get_content()
            
            # Проверяем размер секции
            if sect.size > 100 * 1024 * 1024:  # Пропускаем секции больше 100MB
                section_name = sect.sectname.decode('utf-8').strip('\x00')
                size_mb = sect.size / 1024 / 1024
                print(f"Пропуск большой секции {section_name} (размер: {size_mb:.2f}MB)")
                return b''
            
            # Иначе читаем данные из файла порциями
            data = bytearray()
            with open(self.file_path, 'rb') as f:
                f.seek(sect.offset)
                remaining = sect.size
                
                while remaining > 0:
                    chunk_size = min(remaining, self.chunk_size)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    data.extend(chunk)
                    remaining -= len(chunk)
                    
            return bytes(data)
            
        except Exception as e:
            print(f"Ошибка при чтении данных секции: {e}")
            return b''

    def _analyze_section(self, header, sect) -> List[EmbeddedData]:
        """Анализ секции на наличие встроенных данных"""
        results = []
        
        try:
            section_name = sect.sectname.decode('utf-8').strip('\x00')
            
            # Пропускаем секции, которые обычно не содержат интересных данных
            if section_name in ('__text', '__stubs', '__stub_helper'):
                return results
            
            section_data = self.get_section_data(header, sect)
            
            if not section_data:
                return results
                
            # Анализ строк в секции __cstring
            if section_name == '__cstring':
                results.extend(self._analyze_cstring_section(section_data, section_name))
            
            # Анализ строк в секциях Objective-C
            elif section_name in ('__objc_methname', '__objc_classname'):
                results.extend(self._analyze_objc_section(section_data, section_name))
            
            # Анализ чувствительных данных
            sensitive_findings = self._analyze_sensitive_data(section_data, sect.offset)
            for data_type, data_offset, found_text in sensitive_findings:
                results.append(EmbeddedData(
                    section=section_name,
                    offset=data_offset,
                    size=len(found_text.encode('utf-8')),
                    data_type=f"Sensitive_{data_type}",
                    content=found_text[:50] + "..." if len(found_text) > 50 else found_text
                ))
                
            # Анализ сигнатур файлов
            for sig_type, signature in self.signatures.items():
                if section_data.startswith(signature):
                    results.append(EmbeddedData(
                        section=section_name,
                        offset=sect.offset,
                        size=len(signature),
                        data_type=sig_type,
                        content=section_data[:min(50, len(section_data))]
                    ))
                    
            # Анализ криптографических констант
            for const_name, const_data in self.crypto_constants.items():
                if const_data in section_data:
                    offset = sect.offset + section_data.find(const_data)
                    results.append(EmbeddedData(
                        section=section_name,
                        offset=offset,
                        size=len(const_data),
                        data_type=f"Crypto_{const_name}",
                        content=const_data
                    ))
                    
        except Exception as e:
            print(f"Ошибка при анализе секции {section_name}: {str(e)}")
            
        return results

    def analyze(self) -> List[EmbeddedData]:
        """Анализ всех встроенных данных"""
        all_data = []
        
        for header in self.macho.headers:
            for cmd in header.commands:
                if cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    for sect in cmd[2]:
                        all_data.extend(self._analyze_section(header, sect))
                        
        return all_data 