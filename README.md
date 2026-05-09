# IPbrowse

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0-7f52ff.svg?logo=kotlin&logoColor=white)](https://kotlinlang.org/)
[![Android](https://img.shields.io/badge/android-26%2B-3ddc84.svg?logo=android&logoColor=white)](https://www.android.com/)
[![Jetpack Compose](https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285f4.svg)](https://developer.android.com/jetpack/compose)

Сканер локальной сети с графическим интерфейсом. Десктоп — Python +
PySide6, Android — Kotlin + Jetpack Compose. Сетевая логика общая по
смыслу: TCP-connect сканер портов, реестр IANA, тёмная тема Catppuccin
на обеих платформах.

## Возможности

- Ping-сканирование подсетей, диапазонов и отдельных IP
- Определение **имени хоста** (reverse DNS)
- Получение **MAC-адресов** из ARP-таблицы
- Определение **производителя** устройства по OUI
- Сканирование **открытых портов** (TCP) с распознаванием популярных сервисов
- Многопоточное сканирование (до 512 потоков)
- Фильтрация и сортировка результатов в реальном времени
- Экспорт результатов в **CSV** и **JSON**
- Современный тёмный интерфейс (Catppuccin)

## Скриншот

Главное окно содержит панель параметров, список найденных устройств с
колонками: Статус, IP, Имя хоста, MAC, Производитель, Время отклика, Открытые
порты, а также строку статуса с прогресс-баром.

## Установка

```bash
git clone https://github.com/Pomidor8639/IPbrowse.git
cd IPbrowse
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
```

## Запуск

```bash
python app.py
```

## Использование

1. В поле **Цель** укажите подсеть, диапазон или отдельный IP. Поддерживаются
   форматы:
   - `192.168.1.0/24` — целая подсеть в CIDR
   - `192.168.1.1-50` — диапазон последних октетов
   - `192.168.1.1, 192.168.1.5` — список адресов
   - `10.0.0.1` — одиночный адрес
2. Нажмите **Авто** для автоматического определения локальной подсети.
3. Настройте параметры (таймаут, количество потоков, набор портов).
4. Нажмите **Сканировать**. Результаты появляются в таблице по мере поступления.
5. Через кнопку **Экспорт** результаты можно сохранить в CSV или JSON.

## Использование из CLI

Модуль `scanner.py` можно запустить напрямую без GUI:

```bash
python scanner.py 192.168.1.0/24
```

## Android-версия

Полноценный Android-клиент лежит в `android/`. Это отдельный
Gradle-проект на **Kotlin 2.0** + **Jetpack Compose** + **Material 3**,
тёмная тема Catppuccin одна-в-один с десктопом. Сетевая логика
портирована из `scanner.py` и переписана под корутины: ping
(TCP-fallback на 80 / 443 / 22 / 445 / 53 / 8080, потому что
ICMP-echo на Android без root недоступен), TCP-connect-сканер портов,
снятие баннеров (`-sV`), массовое сканирование, реестр IANA из
`res/raw/ports.csv`. Кнопка «Узнать больше» по порту открывает поиск
Google в локали `hl=ru`, как в десктопе.

`min-sdk` 26 (Android 8.0), `target-sdk` 34. Пять вкладок: «Локальная
сеть», «Внешние сети», «Wi-Fi», «Массовое сканирование», «О программе».

### Сборка APK

```bash
cd android
./gradlew assembleDebug          # → app/build/outputs/apk/debug/app-debug.apk
```

Перед первым запуском создайте `android/local.properties`:

```properties
sdk.dir=C\:\\Users\\<user>\\AppData\\Local\\Android\\Sdk
```

JDK 17 toolchain Gradle подтянет сам через
`org.gradle.toolchains.foojay-resolver-convention`. Запускать
`gradlew` можно из JBR Android Studio (Java 21).

### Ограничения Android-версии

- Без root настоящий ICMP-ping и доступ к ARP-таблице соседей
  невозможны — это ограничение платформы. MAC и vendor у обычных
  хостов будут пустые; для шлюза заполняются по `LinkProperties`.
- Никакого nmap-инсталлера / nmap-флагов на Android нет — это
  десктопная фича.

Подробнее о структуре кода и решениях — `AGENTS.md` (локальный, не
коммитится).

## Структура проекта

```
IPbrowse/
├── app.py                    # PySide6 GUI (десктоп)
├── scanner.py                # логика сканирования (десктоп)
├── ports.csv                 # реестр портов IANA
├── android/                  # Android-версия
│   ├── app/src/main/kotlin/
│   │   └── com/ipbrowse/     # MainActivity, scanner/, ui/
│   ├── app/src/main/res/raw/ports.csv
│   ├── build.gradle.kts
│   └── settings.gradle.kts
├── resources/icon.png        # общая иконка приложения
├── requirements.txt          # зависимости (десктоп)
└── README.md
```

## Замечания

- На некоторых системах для получения MAC-адресов требуется, чтобы хост уже
  был в ARP-кэше. Программа делает ping перед опросом ARP, поэтому в большинстве
  случаев MAC определяется автоматически.
- В Windows ICMP-пинг не требует прав администратора, так как используется
  системная утилита `ping`.
- Для определения вендора по MAC-адресу при первом запуске библиотека
  `mac-vendor-lookup` загружает базу OUI (несколько МБ).

## Лицензия

MIT
