import unittest
import os
from src.core.header_analyzer import HeaderAnalyzer
from macholib.MachO import MachO

class TestHeaderAnalyzer(unittest.TestCase):
    def setUp(self):
        """Подготовка тестового окружения"""
        self.test_file_path = os.path.join(os.path.dirname(__file__), '../target_files/test_app_with_fstack')
        if not os.path.exists(self.test_file_path):
            self.skipTest(f"Тестовый файл {self.test_file_path} не найден")
        self.macho_file = MachO(self.test_file_path)
        self.header_analyzer = HeaderAnalyzer(self.macho_file)

    def test_analyze_magic(self):
        """Тест проверки магического числа"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]['header']
            magic = self.header_analyzer._get_magic(header_info)
            
            self.assertIsInstance(magic, str)
            self.assertIn(magic, ['MH_MAGIC', 'MH_CIGAM', 'MH_MAGIC_64', 'MH_CIGAM_64'])
        except Exception as e:
            self.fail(f"Тест магического числа завершился с ошибкой: {str(e)}")

    def test_analyze_cpu_type(self):
        """Тест проверки типа CPU"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]
            self.assertIsInstance(header_info, dict)
            self.assertIn('cpu_type', header_info)
            self.assertIsInstance(header_info['cpu_type'], str)
            self.assertIn(header_info['cpu_type'], ['x86_64', 'arm64'])
        except Exception as e:
            self.fail(f"Тест типа CPU завершился с ошибкой: {str(e)}")

    def test_analyze_file_type(self):
        """Тест проверки типа файла"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]['header']
            self.assertIsInstance(header_info.filetype, str)
            self.assertIn(header_info.filetype.upper(), ['EXECUTE', 'DYLIB', 'BUNDLE', 'OBJECT'])
        except Exception as e:
            self.fail(f"Тест типа файла завершился с ошибкой: {str(e)}")

    def test_analyze_flags(self):
        """Тест проверки флагов"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]['header'].header

            flags = self.header_analyzer._get_flags(header_info.flags)

            self.assertIsInstance(flags, list)
            # Проверяем наличие важных флагов
            important_flags = ['MH_NOUNDEFS', 'MH_DYLDLINK', 'MH_TWOLEVEL', 'MH_PIE']
            found_flag = False
            for flag in important_flags:
                if flag in flags:
                    found_flag = True
                    break
            self.assertTrue(found_flag, "Важные флаги не найдены")
        except Exception as e:
            self.fail(f"Тест флагов завершился с ошибкой: {str(e)}")

    def test_analyze_commands(self):
        """Тест проверки команд загрузки"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]
            header_info = header_info['header'].header
            #self.assertIn('ncmds', header_info)
            #self.assertIn('sizeofcmds', header_info)
            self.assertIsInstance(header_info.ncmds, int)
            self.assertIsInstance(header_info.sizeofcmds, int)
            self.assertGreater(header_info.ncmds, 0)
            self.assertGreater(header_info.sizeofcmds, 0)
        except Exception as e:
            self.fail(f"Тест команд загрузки завершился с ошибкой: {str(e)}")

    def test_analyze_uuid(self):
        """Тест проверки UUID"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]['header']
            res_uuid = self.header_analyzer._get_load_command_data(header_info)
            self.assertIsInstance(res_uuid, dict)
            self.assertIn('uuid', res_uuid)
            self.assertIsInstance(res_uuid['uuid'], str)
            self.assertEqual(len(res_uuid['uuid']), 32)
        except Exception as e:
            self.fail(f"Тест UUID завершился с ошибкой: {str(e)}")

    def test_analyze_versions(self):
        """Тест проверки версий"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]['header']
            res_build = self.header_analyzer._get_load_command_data(header_info)
            self.assertIsInstance(res_build, dict)
            self.assertIn('source_version', res_build)
            self.assertIn('build_version', res_build)
            self.assertIsInstance(res_build['source_version'], str)
            self.assertIsInstance(res_build['build_version'], str)
        except Exception as e:
            self.fail(f"Тест версий завершился с ошибкой: {str(e)}")

    def test_analyze_segments(self):
        """Тест проверки сегментов"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]
            self.assertIsInstance(header_info, dict)
            self.assertIn('segments', header_info)
            self.assertIsInstance(header_info['segments'], list)
            # Проверяем наличие важных сегментов
            important_segments = ['__PAGEZERO', '__TEXT', '__DATA', '__LINKEDIT']
            for segment in important_segments:
                found = False
                for seg in header_info['segments']:
                    if seg.name == segment:
                        found = True
                        break
                self.assertTrue(found, f"Сегмент {segment} не найден")
        except Exception as e:
            self.fail(f"Тест сегментов завершился с ошибкой: {str(e)}")

    def test_analyze_sections(self):
        """Тест проверки секций"""
        try:
            header = self.header_analyzer.analyze()
            self.assertIsNotNone(header, "Результат анализа не должен быть None")
            self.assertIsInstance(header, list, "Результат должен быть списком")
            if len(header) == 0:
                self.skipTest("Файл не содержит заголовков Mach-O")
            header_info = header[0]
            
            target_sections = []
            for one_segment in header_info['segments']:
                for one_section in one_segment.sections:
                    target_sections.append(one_section.name)
            
            # Проверяем наличие важных секций
            important_sections = ['__text', '__data', '__bss', '__cstring']
            for section in important_sections:
                found = False
                for sec in target_sections:
                    if sec == section:
                        found = True
                        break
                self.assertTrue(found, f"Секция {section} не найдена")
        except Exception as e:
            self.fail(f"Тест секций завершился с ошибкой: {str(e)}")

if __name__ == '__main__':
    unittest.main() 