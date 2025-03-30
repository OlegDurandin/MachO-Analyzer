#!/usr/bin/env python3

from macholib.MachO import MachO
from plugins.malware_patterns_plugin import MalwarePatternsPlugin
from plugins.obfuscation_analyzer_plugin import ObfuscationAnalyzerPlugin
from plugins.network_analyzer_plugin import NetworkAnalyzerPlugin
from plugins.persistence_analyzer_plugin import PersistenceAnalyzerPlugin
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def test_plugin(plugin_class, file_path: str):
    """Тестирует работу плагина"""
    try:
        macho = MachO(file_path)
        plugin = plugin_class(macho, file_path)
        results = plugin.analyze()
        
        # Вывод результатов
        console.print(Panel(f"[bold blue]Результаты анализа плагином {plugin.get_name()}[/bold blue]"))
        
        # Создание таблицы для результатов
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Параметр")
        table.add_column("Значение")
        
        # Добавление результатов в таблицу
        for key, value in results.items():
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    table.add_row(f"{key}.{subkey}", str(subvalue))
            else:
                table.add_row(key, str(value))
        
        console.print(table)
        console.print()
        
    except Exception as e:
        console.print(f"[red]Ошибка при тестировании плагина {plugin_class.__name__}: {str(e)}[/red]")

def test_import_export_analyzer():
    """Тестирование плагина анализа импорта/экспорта"""
    from plugins.import_export_analyzer_plugin import ImportExportAnalyzerPlugin
    from macholib.MachO import MachO
    
    test_file = "test_files/security_test"
    macho = MachO(test_file)
    
    # Анализ тестового файла
    plugin = ImportExportAnalyzerPlugin(macho, test_file)
    results = plugin.analyze()
    
    # Проверка наличия основных секций в результатах
    assert "imports" in results
    assert "exports" in results
    assert "dynamic_linking" in results
    assert "risk_assessment" in results
    
    # Проверка импортов
    assert "libraries" in results["imports"]
    assert "symbols" in results["imports"]
    assert "suspicious" in results["imports"]
    
    # Проверка экспортов
    assert "symbols" in results["exports"]
    assert "functions" in results["exports"]
    assert "variables" in results["exports"]
    
    # Проверка динамического связывания
    assert "lazy_bindings" in results["dynamic_linking"]
    assert "non_lazy_bindings" in results["dynamic_linking"]
    assert "weak_bindings" in results["dynamic_linking"]
    
    # Проверка оценки рисков
    assert "level" in results["risk_assessment"]
    assert "reasons" in results["risk_assessment"]
    assert "recommendations" in results["risk_assessment"]
    
    print("ImportExportAnalyzer tests passed successfully")

def main():
    test_file = "test_files/security_test"
    
    # Тестирование плагина анализа подозрительных паттернов
    test_plugin(MalwarePatternsPlugin, test_file)
    
    # Тестирование плагина анализа обфускации
    test_plugin(ObfuscationAnalyzerPlugin, test_file)
    
    # Тестирование плагина анализа сетевой активности
    test_plugin(NetworkAnalyzerPlugin, test_file)
    
    # Тестирование плагина анализа персистентности
    test_plugin(PersistenceAnalyzerPlugin, test_file)

    test_import_export_analyzer()

if __name__ == "__main__":
    main() 