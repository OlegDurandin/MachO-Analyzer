
# Magic Numbers
MH_MAGIC = 0xFEEDFACE      # 32-bit Little-Endian
MH_CIGAM = 0xCEFAEDFE      # 32-bit Big-Endian
MH_MAGIC_64 = 0xFEEDFACF   # 64-bit Little-Endian
MH_CIGAM_64 = 0xCFFAEDFE   # 64-bit Big-Endian

# CPU Type константы
CPU_ARCH_ABI64 = 0x01000000
CPU_ARCH_ABI64_32 = 0x02000000
CPU_TYPE_ARM = 0xc
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64
CPU_TYPE_ARM64_32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32
CPU_TYPE_X86 = 0x7
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_POWERPC = 18
CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64

FLAG_DESCRIPTIONS = {
    "MH_NOUNDEFS": "Не содержит неопределенных символов",
    "MH_INCRLINK": "Увеличенное связывание",
    "MH_DYLDLINK": "Динамически связанный",
    "MH_BINDATLOAD": "Связывание при загрузке",
    "MH_PREBOUND": "Предварительно связанный",
    "MH_SPLIT_SEGS": "Разделенные сегменты",
    "MH_LAZY_INIT": "Ленивая инициализация",
    "MH_TWOLEVEL": "Двухуровневое пространство имен",
    "MH_FORCE_FLAT": "Принудительное плоское пространство имен",
    "MH_NOMULTIDEFS": "Не допускает множественных определений",
    "MH_NOFIXPREBINDING": "Не исправляет предварительное связывание",
    "MH_PREBINDABLE": "Может быть предварительно связан",
    "MH_ALLMODSBOUND": "Все модули связаны",
    "MH_SUBSECTIONS_VIA_SYMBOLS": "Подсекции через символы",
    "MH_CANONICAL": "Канонический",
    "MH_WEAK_DEFINES": "Слабые определения",
    "MH_BINDS_TO_WEAK": "Связывается со слабыми символами",
    "MH_ALLOW_STACK_EXECUTION": "Разрешает выполнение стека",
    "MH_ROOT_SAFE": "Безопасен для root",
    "MH_SETUID_SAFE": "Безопасен для setuid",
    "MH_NO_REEXPORTED_DYLIBS": "Не реэкспортирует динамические библиотеки",
    "MH_PIE": "Position Independent Executable",
    "MH_DEAD_STRIPPABLE_DYLIB": "Может быть удалена, если не используется",
    "MH_HAS_TLV_DESCRIPTORS": "Содержит дескрипторы Thread Local Storage",
    "MH_NO_HEAP_EXECUTION": "Запрещает выполнение в куче",
    "MH_APP_EXTENSION_SAFE": "Безопасен для расширений приложений",
    "MH_NLIST_OUTOFSYNC_WITH_DYLDINFO": "Список символов не синхронизирован с dyld_info",
    "MH_SIM_SUPPORT": "Поддержка симулятора",
    "MH_DYLIB_IN_CACHE": "Динамическая библиотека находится в кэше dyld"
} 