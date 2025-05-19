# Автоматизация статического анализа бинарных файлов с помощью Ghidra API на Python 

## Обзор возможностей Ghidra API

Ghidra предоставляет мощный набор программных интерфейсов, позволяющих управлять внутренними объектами анализа: от загрузчика и декомпилера до элементов представления программы (Function, Listing, Program). С помощью Jython-сценариев можно:

1. Открывать и автоматически анализировать указанный двоичный файл.
2. Перебирать все найденные функции, строить граф вызовов и сохранять его в виде данных.
3. Выявлять известные шаблоны конструкций (поиск строковых функций, memcpy, крипто-библиотек).
4. Собирать метрики по функциям и инструкции (количество перекрытий, глубина вложенности, количество локальных переменных и использование стека).
5. Экспортировать все полученные данные в формате JSON или CSV для объединения с результатами других инструментов.

Далее мы пройдем каждый из пунктов выше пошагово.

## Подготовка окружения

Прежде чем приступить к написанию скриптов, необходимо убедиться, что на вашей системе установлено свежее издание Ghidra (версия 10.x или выше), а также скриптовый движок Jython, который входит в комплект Ghidra. Для удобства работы рекомендуется создать отдельную папку для своих сценариев:

1. Откройте каталог установки Ghidra и перейдите в папку `Ghidra/Features/Python`.
2. Создайте там новую директорию, например, `AutoAnalysis`.
3. Убедитесь, что внутри каталога `AutoAnalysis` нет конфликтующих файлов — вы будете хранить туда свои `.py`-скрипты.

Если вы планируете обращаться к внешним библиотекам (например, для более удобного экспорта JSON), убедитесь, что Jython видит пути к ним: отредактируйте файл `Ghidra/Support/analyzeHeadless` или соответствующий скрипт запуска, добавив в переменную `PYTHONPATH` путь к каталогу с вашими модулями.

## Первый скрипт: загрузка и анализ файла

Начнем с создания самого простого скрипта, который принимает на вход имя исполняемого файла, загружает его в Ghidra и запускает необходимый набор анализаторов. Откройте новый файл `AutoAnalysis/LoadAndAnalyze.py` и вставьте следующий код:

```python
from ghidra.app.script import GhidraScript

class LoadAndAnalyze(GhidraScript):
    def run(self):
        # Получаем путь к целевому файлу
        target_path = askFile('Выберите бинарный файл для анализа', 'Открыть').absolutePath

        # Загружаем программу
        program = self.importer.importByUsingLoader(target_path, False, monitor)

        # Запускаем анализ
        analysis_manager = self.getAnalysisManager(program)
        analysis_manager.initializeOptions(monitor)
        analysis_manager.reAnalyzeAll(program, monitor)

        # Выводим сообщение об успешном завершении
        self.println('Анализ завершен для: {}'.format(program.getName()))

if __name__ == '__main__':
    LoadAndAnalyze().run()
```

В этом коде мы описываем класс-наследник `GhidraScript`, реализуем метод `run`, где последовательно вызываем загрузчик, менеджер анализа и выводим сообщение об окончании. Обратите внимание, что функция `askFile` интерактивно запрашивает у пользователя путь к файлу, а `analysis_manager.reAnalyzeAll` обеспечивает применение всех стандартных анализаторов Ghidra.

### Пояснения к коду

В первом фрагменте мы обращаемся к диалогу выбора файла. Во втором — используем `importByUsingLoader`, чтобы Ghidra автоматически определила формат (ELF, PE, Mach-O). Затем контейнер `AnalysisManager` инициализирует все параметры по умолчанию и запускает анализ. Такой шаблон станет основой для всех последующих сценариев, поэтому я рекомендую скопировать его к себе и сохранить под базовым именем.

## Извлечение функций и построение Call Graph

После того как файл загружен и проанализирован, нам нужно перебрать все функции и собрать информацию об их вызовах. Для этого создадим скрипт `AutoAnalysis/CallGraphExtractor.py`:

```python
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function
import json

class CallGraphExtractor(GhidraScript):
    def run(self):
        program = currentProgram
        fm = program.getFunctionManager()
        functions = fm.getFunctions(True)
        call_graph = {}

        for func in functions:
            callees = []
            # Получаем итератор по всем call-операторам в функции
            instructions = getInstructions(func.getBody(), True)
            for instr in instructions:
                if instr.getMnemonicString().upper().startswith('CALL'):
                    ref = instr.getPrimaryReference(0)
                    if ref and ref.getReferenceType().isCall():
                        target = ref.getToAddress()
                        callee = fm.getFunctionAt(target)
                        if callee:
                            callees.append(callee.getName())
            call_graph[func.getName()] = callees

        # Экспортируем в JSON
        output = askFile('Сохранить Call Graph', 'Сохранить')
        with open(output.absolutePath, 'w') as f:
            json.dump(call_graph, f, indent=2, ensure_ascii=False)
        self.println('Call Graph сохранен в {}'.format(output))

if __name__ == '__main__':
    CallGraphExtractor().run()
```

Здесь мы перебираем все функции через `getFunctions(True)`, после чего внутри каждой функции сканируем инструкции на предмет инструкций `CALL`. Шаг за шагом мы получаем ссылки на целевые адреса, определяем функцию-цель и добавляем ее имя в список вызовов. В конце формируется словарь `call_graph`, который сохраняется в JSON.

## Распознавание и переименование типовых конструкций

Автоматическое переименование функций существенно облегчает дальнейший разбор кода. Например, стоит найти все вызовы `memcpy` или функций крипто-библиотек, и дать им осмысленные имена. Создадим скрипт `PatternRecognizer.py`:

```python
from ghidra.app.script import GhidraScript
import re

class PatternRecognizer(GhidraScript):
    def run(self):
        program = currentProgram
        byte_patterns = [
            (b'\x48\x83\xec\x08', 'stack_frame_setup'),
            (b'\x8b\x45\x0c', 'load_arg'),
        ]
        fm = program.getFunctionManager()

        # Проходим по всем функциям
        for func in fm.getFunctions(True):
            body = getBytes(func.getEntryPoint(), func.getBody().getNumAddresses())
            for pattern, name in byte_patterns:
                if body is not None and pattern in body:
                    new_name = "{}_{}".format(func.getName(), name)
                    func.setName(new_name, ghidra.program.model.symbol.SourceType.ANALYSIS)
                    break

        # Переименование строковых функций
        for string_ref in getDataReferencesTo(currentProgram.getDefaultPointerSize()):
            data = getDataAt(string_ref.getFromAddress())
            if data and data.isDefined() and data.getValue().startswith("printf"):
                func = fm.getFunctionContaining(string_ref.getFromAddress())
                if func:
                    func.setName("PRINTF_{}".format(func.getEntryPoint()), 
                                 ghidra.program.model.symbol.SourceType.USER_DEFINED)

        self.println('Паттерны распознаны и функции переименованы.')

if __name__ == '__main__':
    PatternRecognizer().run()
```

В этом примере мы задаем список байтовых паттернов и проверяем, встречаются ли они в теле функции. Если да, то добавляем к имени функции суффикс, поясняющий её роль. Затем отдельно обрабатываем ссылки на данные, содержащие строки формата (`printf`), и переименовываем соответствующие функции.

## Сбор метрик по функциям

Чтобы получить количественную оценку сложности или глубины функций, необходимо собрать такие метрики, как число перекрывающихся областей, глубину вложенности ветвлений и использование локальных (стековых) переменных. Скрипт `MetricsCollector.py` может выглядеть следующим образом:

```python
from ghidra.app.script import GhidraScript
import csv

class MetricsCollector(GhidraScript):
    def run(self):
        program = currentProgram
        fm = program.getFunctionManager()
        metrics = []

        for func in fm.getFunctions(True):
            instr_count = 0
            max_depth = 0
            local_vars = len(func.getLocalVariables())

            # Подсчет инструкций и глубины ветвлений
            stack = [(func.getEntryPoint(), 0)]
            visited = set()
            while stack:
                addr, depth = stack.pop()
                if addr in visited:
                    continue
                visited.add(addr)
                if depth > max_depth:
                    max_depth = depth

                instr = getInstructionAt(addr)
                while instr and instr.getAddress() in func.getBody():
                    instr_count += 1
                    mnemonic = instr.getMnemonicString()
                    if mnemonic in ('JMP', 'JNZ', 'JE', 'JL', 'JLE'):
                        # Добавляем переход в стек с увеличением глубины
                        for ref in instr.getReferencesFrom():
                            if ref.getReferenceType().isConditional() or ref.getReferenceType().isJump():
                                stack.append((ref.getToAddress(), depth + 1))
                    elif mnemonic == 'RET':
                        break
                    instr = instr.getNext()

            metrics.append({
                'name': func.getName(),
                'instructions': instr_count,
                'max_depth': max_depth,
                'local_vars': local_vars
            })

        # Экспортируем в CSV
        output = askFile('Сохранить метрики', 'Сохранить', 'func_metrics.csv')
        with open(output.absolutePath, 'w', newline='') as csvfile:
            fieldnames = ['name', 'instructions', 'max_depth', 'local_vars']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for m in metrics:
                writer.writerow(m)

        self.println('Метрики функций сохранены в CSV.')

if __name__ == '__main__':
    MetricsCollector().run()
```

В этом сценарии мы обходим каждую функцию, выполняем обход графа выполнения для подсчета инструкций и оценки глубины вложенности ветвлений, а также считаем число локальных переменных. Наконец, формируем CSV-файл с результатами.

## Экспорт и объединение результатов

После выполнения всех предыдущих скриптов вы получите на диске несколько файлов: `call_graph.json`, `func_metrics.csv` и, возможно, дополнительные JSON-файлы с переименованными функциями. Для дальнейшего объединения с данными других инструментов (например, динамического анализа) можно использовать Python-скрипт вне Ghidra:

```python
import json
import csv

def load_call_graph(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_metrics(path):
    metrics = {}
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            metrics[row['name']] = {
                'instructions': int(row['instructions']),
                'max_depth': int(row['max_depth']),
                'local_vars': int(row['local_vars'])
            }
    return metrics

if __name__ == '__main__':
    cg = load_call_graph('call_graph.json')
    mt = load_metrics('func_metrics.csv')

    merged = []
    for func, callees in cg.items():
        data = mt.get(func, {})
        merged.append({
            'function': func,
            'callees': len(callees),
            'instructions': data.get('instructions', 0),
            'max_depth': data.get('max_depth', 0),
            'local_vars': data.get('local_vars', 0)
        })

    # Сохраняем общий отчет
    with open('merged_report.csv', 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['function', 'callees', 'instructions', 'max_depth', 'local_vars']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in merged:
            writer.writerow(row)
    print('Объединенный отчет сохранен в merged_report.csv')
```

Этот утилитарный скрипт читает данные из ранее созданных файлов и сводит их в единый CSV-отчет, где для каждой функции указано число вызовов `callees`, общее число инструкций, максимальная глубина ветвлений и количество локальных переменных. Готовый файл `merged_report.csv` может быть загружен в табличный редактор, BI-систему или объединен с результатами динамического анализа.
