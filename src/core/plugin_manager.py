import os
import importlib
import inspect
from typing import Dict, List, Type, Any, Optional
from .plugin_base import MachOPlugin

class PluginManager:
    """Менеджер для загрузки и управления плагинами"""
    
    def __init__(self):
        self.plugins: Dict[str, Type[MachOPlugin]] = {}
        self.loaded_plugins: Dict[str, MachOPlugin] = {}
    
    def load_plugins(self, plugin_dir: str = "plugins"):
        """Загружает все плагины из указанной директории"""
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir)
        
        t = os.listdir(plugin_dir)

        for file in os.listdir(plugin_dir):
            if file.endswith(".py") and not file.startswith("__"):
                module_name = f"plugins.{file[:-3]}"
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, MachOPlugin) and 
                            obj != MachOPlugin):
                            self.register_plugin(obj)
                except Exception as e:
                    print(f"Ошибка загрузки плагина {file}: {str(e)}")
    
    def register_plugin(self, plugin_class: Type[MachOPlugin]):
        """Регистрирует новый плагин"""
        try:
            # Получаем имя плагина напрямую из класса
            name = plugin_class.get_name()
            self.plugins[name] = plugin_class
        except Exception as e:
            print(f"Ошибка при регистрации плагина {plugin_class.__name__}: {str(e)}")
    
    def get_plugin(self, name: str) -> Optional[Type[MachOPlugin]]:
        """Получает плагин по имени"""
        return self.plugins.get(name)
    
    def get_all_plugins(self) -> Dict[str, Type[MachOPlugin]]:
        """Получает все зарегистрированные плагины"""
        return self.plugins.copy()
    
    def clear_plugins(self):
        """Очищает список зарегистрированных плагинов"""
        self.plugins.clear()
    
    def get_available_plugins(self) -> List[str]:
        """Возвращает список доступных плагинов"""
        return list(self.plugins.keys())
    
    def get_plugin_info(self, plugin_name: str) -> Dict[str, str]:
        """Возвращает информацию о плагине"""
        plugin_class = self.plugins.get(plugin_name)
        if plugin_class:
            return {
                "name": plugin_class.get_name(),
                "description": plugin_class.get_description(),
                "version": plugin_class.get_version()
            }
        return {}
    
    def instantiate_plugin(self, plugin_name: str, macho, file_path: str) -> Optional[MachOPlugin]:
        """Создает экземпляр плагина"""
        plugin_class = self.plugins.get(plugin_name)
        if plugin_class:
            return plugin_class(macho, file_path)
        return None
    
    def run_plugin(self, plugin_name: str) -> Dict[str, Any]:
        """Запускает указанный плагин"""
        plugin = self.instantiate_plugin(plugin_name, None, None)
        if plugin:
            return plugin.analyze()
        return {} 