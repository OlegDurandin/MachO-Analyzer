from src.core.sign_analyzer import SignAnalyzer

def main():
    analyzer = SignAnalyzer('/Applications/Safari.app')
    info = analyzer.analyze()
    
    print('=== Signature Information ===')
    print(f'Status: {info.status}')
    print(f'Type: {info.sign_type}')
    print(f'Timestamp: {info.timestamp}')
    
    if info.developer_info:
        print('\n=== Developer Information ===')
        for key, value in info.developer_info.items():
            print(f'{key}: {value}')
    
    print('\n=== Analyzed Entitlements ===')
    for category, items in info.analyzed_entitlements.items():
        if items:  # Показываем только непустые категории
            print(f'\n{category.upper()}:')
            for key, value in items[:5]:  # Показываем первые 5 элементов каждой категории
                if isinstance(value, (list, dict)):
                    print(f'  - {key}: [complex value]')
                else:
                    print(f'  - {key}: {value}')
            if len(items) > 5:
                print(f'  ... and {len(items) - 5} more')
                
if __name__ == '__main__':
    main() 