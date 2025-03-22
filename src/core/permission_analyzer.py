from typing import Dict, Any
from macholib.MachO import MachO
from .sign_analyzer import SignAnalyzer

class PermissionAnalyzer:
    """Анализатор разрешений в Mach-O файлах"""
    
    def __init__(self, macho: MachO, file_path: str):
        self.macho = macho
        self.file_path = file_path
        self.sign_analyzer = SignAnalyzer(file_path)
        
    def analyze(self) -> Dict[str, Any]:
        """Анализ разрешений"""
        permissions = {}
        
        # Получаем информацию о подписи и entitlements
        sign_info = self.sign_analyzer.analyze()
        if sign_info and sign_info.analyzed_entitlements:
            # Объединяем все разрешения из разных категорий
            for category, items in sign_info.analyzed_entitlements.items():
                for key, value in items:
                    permissions[key] = value
                    
        return permissions 