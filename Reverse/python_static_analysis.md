# Автоматизация статического анализа бинарных файлов с помощью Radare2 и r2pipe на Python

## Введение

В последние годы автоматизация реверс-инжиниринга становится неотъемлемой частью практики анализа бинарных файлов. В соревнованиях Capture The Flag ограниченные по времени задачи вынуждают искать способы сократить рутинную работу: ручной просмотр дизассемблера и поиск потенциальных уязвимостей отвлекает внимание от действительно важных моментов. Инструмент Radare2, будучи универсальным фреймворком для реверс-анализа, предоставляет богатый набор команд для исследования исполняемого кода и структуры бинарников, однако взаимодействие с ним через командную строку по-прежнему требует многократного ввода однотипных команд. Подключение библиотеки r2pipe и написание скриптов на Python позволяет объединить возможности Radare2 и гибкость Python, автоматизируя процессы извлечения строк, функций, потенциально опасных вызовов и даже поиска ROP-цепочек.

В этой статье мы последовательно рассмотрим, как установить и настроить Radare2 и r2pipe, разберём простые примеры скриптов, которые могут сэкономить десятки часов ручной работы, перейдём к более сложным техникам — распознаванию ROP-цепочек и анализу структуры ELF/PE, а в финале покажем, как собрать результаты анализа в удобный отчёт в формате CSV или JSON и интегрировать всё это в CI/CD-пайплайн для массового сканирования.

## Установка и базовая настройка Radare2 и r2pipe

Перед тем как приступить к автоматизации, необходимо убедиться, что на вашей системе установлены две ключевые составляющие: сам фреймворк Radare2 и Python-библиотека r2pipe. Рассмотрим процесс установки шаг за шагом.

**Шаг 1. Установка Radare2.**

Для начала клонируем репозиторий с официального GitHub и соберём инструменты из исходников. Откройте терминал и выполните следующие команды:

```bash
git clone https://github.com/radareorg/radare2.git
cd radare2
./sys/install.sh
```

После выполнения скрипта в системе появятся утилиты `r2`, `r2pm`, `radiff2` и другие. Проверьте версию:

```bash
r2 --version
```

Ожидаемый вывод должен содержать информацию о текущей версии (например, `radare2 6.x.x`). Если версия менее свежая, обновите её через `r2pm update` и `r2pm upgrade`.

**Шаг 2. Установка r2pipe.**

Вторая часть — установка Python-модуля для взаимодействия с Radare2 из скриптов. В среде Python 3 достаточно выполнить:

```bash
pip install r2pipe
```

Если вы используете виртуальное окружение (`venv` или `virtualenv`), активируйте его перед установкой. Удостоверьтесь, что импорт работает без ошибок:

```python
import r2pipe
print(r2pipe.__version__)
```

**Шаг 3. Подготовка проекта.**

Создайте каталог для скриптов:

```bash
mkdir r2_automation
cd r2_automation
```

Здесь будем хранить все наши скрипты и шаблоны для отчётов. В дальнейшем настройте файл `requirements.txt`, чтобы зафиксировать зависимость:

```
r2pipe>=5.0.0
```

Теперь окружение готово, и можно переходить к созданию первых автоматизированных задач.

## Простые скрипты для ускорения реверс-анализа

### Выгрузка всех строк и поиск «интересных» подсказок

Одной из часто выполняемых операций при статическом анализе является извлечение строк из бинарника и попытка найти среди них очевидные ключи: пароли, URL, имена файлов конфигурации. Radare2 предоставляет команду `iz` для получения списка всех строк, а r2pipe позволяет легко получить результат в виде текста или JSON. Пример минимального скрипта:

```python
import r2pipe
import re

def extract_strings(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')  # Автоанализ: функции, графы, пересечения
    raw = r2.cmd('iz')  # Получаем строки в текстовом формате
    candidates = []
    for line in raw.splitlines():
        if re.search(r'https?://', line) or re.search(r'pass(word)?[:=]\S+', line, re.IGNORECASE):
            candidates.append(line.strip())
    return candidates

if __name__ == '__main__':
    import sys
    for s in extract_strings(sys.argv[1]):
        print(s)
```

В этом примере мы вызываем `r2.cmd('aaa')` для того, чтобы Radare2 провёл полный автоплан анализа: обнаружил функции, переменные, графы переходов. Затем команда `iz` выдаёт все текстовые строки, обнаруженные в секциях `.rodata` и в других сегментах, подходящих для хранения литералов. Регулярные выражения ищут подстроки `http://` или `https://`, а также простейшие варианты указания пароля, такие как `password:` или `pass=`. Такой скрипт сразу же выведет всё, что может быть полезным подсказкам при решении CTF-задачи.

### Перечисление функций и их сигнатур

Для более глубокой работы может потребоваться список всех функций и их «сигнатур» — простое описание начала байткода, позволяющее сравнить функцию с набором шаблонов известных уязвимостей (например, паттернами переполнения буфера). Радикально ручной подход — просматривать дизассемблированные блоки одна за другой. Автоматический скрипт может выглядеть так:

```python
import r2pipe
import hashlib
import json

# Пример шаблона: хэш первых 16 байт кода уязвимой функции
TEMPLATES = {
    'vuln_func': '3a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d',
}

def list_functions(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')
    funcs = r2.cmdj('aflj')  # Получаем функции в JSON
    findings = []
    for f in funcs:
        addr = f['offset']
        size = min(f['size'], 16)
        # Читаем первые size байт
        bytes_hex = r2.cmd(f'px {size} @ {addr}').split()
        raw_bytes = bytes.fromhex(''.join(bytes_hex[1:]))
        h = hashlib.md5(raw_bytes).hexdigest()
        for name, tmpl_hash in TEMPLATES.items():
            if h == tmpl_hash:
                findings.append({'function': f['name'], 'type': name, 'address': hex(addr)})
    return findings

if __name__ == '__main__':
    import sys
    print(json.dumps(list_functions(sys.argv[1]), indent=2, ensure_ascii=False))
```

Здесь команда `aflj` возвращает массив объектов с описанием функций: имя, адрес, размер, количество базовых блоков. Мы читаем первые 16 байт каждой функции, вычисляем MD5 и сравниваем с заранее подготовленными шаблонами. При совпадении скрипт выводит найденную уязвимую функцию с аннотацией, какую именно сигнатуру мы обнаружили.

### Массовый экспорт дизассемблированных фрагментов в файлы

Если требуется вручную просматривать код, удобнее иметь дизассемблированный вывод для каждой функции в отдельном текстовом файле, вместо навигации по интерактивному интерфейсу Radare2. Следующий скрипт экспортирует дизассемблер в формате `pd` (pseudo-disassembly) для каждой функции:

```python
import os
import r2pipe

def export_disasm(filepath, outdir='disasm'):
    os.makedirs(outdir, exist_ok=True)
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')
    funcs = r2.cmdj('aflj')
    for f in funcs:
        name = f['name'].replace('/', '_')
        addr = f['offset']
        # Формируем дизассемблированный вывод
        disasm = r2.cmd(f'pdf @ {addr}')
        filename = os.path.join(outdir, f'{name}_{addr:x}.asm')
        with open(filename, 'w') as fd:
            fd.write(disasm)

if __name__ == '__main__':
    import sys
    export_disasm(sys.argv[1])
```

После запуска в директории `disasm` появятся файлы вида `sym.func_401000_401000.asm`, содержащие дизассемблированный код с графом и комментариями Radare2. Таким образом, можно открыть любую функцию в текстовом редакторе или IDE и быстро пролистывать большие объёмы кода.

## Расширенные техники анализа

### Автоматическое распознавание упрощённых ROP-цепочек

Return-Oriented Programming (ROP) — популярный метод эксплуатации уязвимостей на уровне управления потоком выполнения. Поиск ROP-гаджетов вручную — трудоёмкая задача, но Radare2 умеет искать маленькие последовательности инструкций, завершающиеся инструкцией `ret`. С помощью r2pipe можно автоматизировать поиск и анализ таких гаджетов.

```python
import r2pipe
import json

def find_rop_chains(filepath, max_chain_length=3):
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')
    # Поиск всех гаджетов с помощью команды agj
    gadgets = r2.cmdj('agj')
    # Отбираем «хорошие» гаджеты длиной до 5 инструкций
    short_gadgets = [g for g in gadgets if len(g.get('ops', [])) <= 5]
    chains = []
    # Простая комбинация первых трех подходящих гаджетов в цепочку
    for i in range(len(short_gadgets) - max_chain_length + 1):
        chain = short_gadgets[i:i + max_chain_length]
        addresses = [hex(g['offset']) for g in chain]
        chains.append(addresses)
    return chains

if __name__ == '__main__':
    import sys
    rop = find_rop_chains(sys.argv[1])
    print(json.dumps(rop, indent=2))
```

В этом примере мы применяем команду `agj` (all gadgets in JSON), фильтруем гаджеты, содержащие не более пяти операций (`ops`), а затем формируем простейшие цепочки из трёх адресов, где каждый адрес указывает на начало гаджета. Более сложные алгоритмы могут учитывать регистры, параметры функций и ограничения контекста, но даже этот базовый подход даёт старт для автоматизированной пост-эксплуатации.

### Парсинг структуры ELF/PE и поиск потенциально небезопасных вызовов

Статический анализ импортов и экспортов бинарника позволяет выявить функции, связанные с небезопасными операциями: `strcpy`, `system`, `memcpy` и аналогами. Radare2 умеет выводить таблицу импортов и информацию о формате ELF/PE в JSON. Рассмотрим пример парсера:

```python
import r2pipe
import json

UNSAFE = {'strcpy', 'strcat', 'sprintf', 'gets', 'system', 'memcpy'}

def analyze_imports(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')
    # Получаем информацию об импортированных функциях
    imports = r2.cmdj('iij')
    findings = []
    for imp in imports:
        name = imp.get('name')
        if name in UNSAFE:
            findings.append({'function': name, 'plt': hex(imp['plt'])})
    return findings

if __name__ == '__main__':
    import sys
    result = analyze_imports(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False))
```

Сначала мы вызываем `aaa`, затем через `iij` получаем список всех импортируемых функций: имя, адрес PLT (Procedure Linkage Table), библиотеку-источник и другие свойства. Сравнение с множеством `UNSAFE` позволяет быстро обнаружить подозрительные векторы для атак, например, вызов `system("sh")` или опасные операции копирования памяти без проверки длины.

## Интеграция результатов в отчёт

Собрав различные типы находок (строки, функции, ROP-цепочки, небезопасные вызовы), имеет смысл объединить их в единый отчёт, удобный для дальнейшего анализа. Как правило, форматы CSV и JSON наиболее универсальны: их можно легко импортировать в таблицы, визуализировать или применять скрипты обработки.

Ниже пример формирования CSV-файла с описанием потенциальных уязвимостей:

```python
import csv
import json

def merge_findings(strings, funcs, imports, rop):
    # Столбцы: тип, имя/описание, детали
    rows = []
    for s in strings:
        rows.append({'type': 'string', 'name': s, 'details': ''})
    for f in funcs:
        rows.append({'type': 'vuln_func', 'name': f['function'], 'details': f['type']})
    for imp in imports:
        rows.append({'type': 'unsafe_import', 'name': imp['function'], 'details': imp['plt']})
    for chain in rop:
        rows.append({'type': 'rop_chain', 'name': ' -> '.join(chain), 'details': ''})
    return rows

def write_csv(rows, outpath='report.csv'):
    with open(outpath, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['type', 'name', 'details'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

if __name__ == '__main__':
    import sys
    # Заготовка вызовов предыдущих функций
    from extract_strings import extract_strings
    from list_functions import list_functions
    from analyze_imports import analyze_imports
    from find_rop_chains import find_rop_chains

    binary = sys.argv[1]
    strs = extract_strings(binary)
    funcs = list_functions(binary)
    imps = analyze_imports(binary)
    rop = find_rop_chains(binary)
    rows = merge_findings(strs, funcs, imps, rop)
    write_csv(rows)
    print(f'Отчёт сохранён в report.csv (строк: {len(rows)})')
```

Здесь мы объединяем результаты четырёх отдельных модулей и формируем единый CSV. Аналогичным образом можно формировать JSON — для этого достаточно заменить код записи на:

```python
with open('report.json', 'w', encoding='utf-8') as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)
```

Полученные файлы легко подхватить внешними средствами визуализации или встроить в систему отчётности.

## Рекомендации по дальнейшему развитию и интеграции в CI/CD

1. **Модульность и повторное использование.** Стоит разделить скрипты на отдельные модули (каждый функционал — отдельный файл), чтобы при необходимости легко заменять или расширять отдельные части анализа.

2. **Версионирование и тестирование.** Храните скрипты в системе контроля версий (Git), добавьте автотесты для проверки правильности парсинга выходных данных Radare2. Это поможет быстро обнаруживать поломки при обновлениях Radare2 или Python-зависимостей.

3. **Интеграция с CI/CD.** Настройте GitHub Actions, GitLab CI или Jenkins для автоматического запуска сканирования при появлении новых бинарников в репозитории. Пример фрагмента `.github/workflows/scan.yml`:

   ```
   name: Static Analysis

   on:
     push:
       paths:
         - 'binaries/**'

   jobs:
     analyze:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v2
         - name: Install dependencies
           run: |
             sudo apt-get update && sudo apt-get install -y radare2
             pip install r2pipe
         - name: Run analysis
           run: |
             python extract_strings.py binaries/${{ github.sha }}.bin > strings.json
             python list_functions.py binaries/${{ github.sha }}.bin > funcs.json
             python analyze_imports.py binaries/${{ github.sha }}.bin > imports.json
             python find_rop_chains.py binaries/${{ github.sha }}.bin > rop.json
         - name: Merge report
           run: |
             python merge_reports.py
         - name: Upload report
           uses: actions/upload-artifact@v2
           with:
             name: analysis-report-${{ github.sha }}
             path: report.csv
   ```

   Такой подход позволит автоматически сканировать все новые сборки и сохранять отчёты как артефакты сборки.

4. **Расширение шаблонов уязвимостей.** Разработайте базу сигнатур на основе хэшей участков кода, регулярных выражений в дизассемблере или машинного обучения: более точные шаблоны помогут избегать ложных срабатываний и находить неизвестные прежде уязвимости.

5. **Визуализация данных.** Для удобства восприятия больших отчётов можно построить дашборды на основе загруженных CSV/JSON. Инструменты типа Grafana, Kibana или собственный React-интерфейс сделают процесс анализа результатов более наглядным.

6. **Автоматическое уведомление.** При обнаружении критических уязвимостей интегрируйте отправку уведомлений в Slack, Telegram или по электронной почте. Это позволит моментально реагировать на появление новых проблем в бинарниках.

## Заключение

Автоматизация статического анализа бинарных файлов с помощью Radare2 и r2pipe на Python открывает широкие возможности для ускорения реверс-инжиниринга: от простой выгрузки строк и определения функций до распознавания ROP-цепочек и поиска небезопасных вызовов. В сочетании с системой отчётности CSV/JSON и CI/CD-пайплайнами это превращает разовые инструменты в полноценно работающий сканер, готовый к интеграции в любые процессы разработки и обеспечения безопасности. Начав с небольших скриптов, вы сможете постепенно вырастить надёжную инфраструктуру анализа, экономя время и ресурсы при решении CTF-задач или в промышленном анализе уязвимостей.
