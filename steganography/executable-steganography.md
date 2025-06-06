# Стеганография в исполняемых файлах

## 1. Краткое введение в ELF 

Стеганография в исполняемых файлах - это сокрытие информации внутри программ. Цель может быть разной: от сокрытия вредоносного кода до защиты авторских прав. 

Мы будем фокусироваться на том, как это можно сделать в формате ELF (Executable and Linkable Format).

ELF - это стандартный формат исполняемых файлов в Linux и других Unix-подобных системах. ELF-файл содержит код, данные и информацию о том, как программа должна быть загружена и запущена. 

Ключевые элементы, которые нам понадобятся, это:

•	Заголовок (Header): Основная информация о файле.

•	Секции (Sections): Разделы файла, содержащие код (.text), данные (.data), неинициализированные данные (.bss), строки (.rodata) и многое другое.

•	Программные заголовки (Program Headers): Описывают, как операционная система должна загрузить секции в память.

Чтобы посмотреть структуру ELF-файла, можно использовать следующие команды:

•	readelf -h <filename> - покажет заголовок.

•	readelf -S <filename> - покажет список секций.

## 2. Padding в ELF 

**2.1 Что такое Padding?**

В контексте ELF, padding – это неиспользуемое пространство внутри файла. Оно может находиться:

•	Между секциями: Для выравнивания начала следующей секции по определенной границе (например, по границе страницы памяти). Это делается для повышения производительности при загрузке программы в память.

•	В конце секции: Хотя это встречается реже, padding может присутствовать и в конце секции.

Padding не содержит полезных данных и игнорируется операционной системой при загрузке и выполнении программы. Именно это делает его идеальным кандидатом для сокрытия информации.

**Как найти Padding?**

1.	Используйте readelf -S <filename>: Эта команда выведет список всех секций в ELF-файле, их размеры (Size) и смещения (Offset).

2.	Сравните смещения и размеры соседних секций: Padding будет находиться между секцией A и секцией B, если Offset(B) > Offset(A) + Size(A). Размер padding будет равен Offset(B) - (Offset(A) + Size(A)).

**Важно:** Padding не является частью какой-либо секции. Это просто “пустое” место в файле. Операционная система знает, где начинаются и заканчиваются секции, и не будет читать данные из области padding.

**2.2 Пример: Создание простого ELF-файла**

Для начала создадим простую программу на C:

```c
#include <stdio.h>

int main() {
    printf("Hello, world!\n");
    return 0;
}
```

Сохраняем этот код в файл hello.c. 

Теперь скомпилируем его:

**gcc hello.c -o hello**

Эта команда создаст исполняемый файл hello в формате ELF.

<img src="https://github.com/linafillippova/articles/blob/main/screens25-04-14/1.png">
 
**2.3 Анализ секций файла hello**

Запускаем команду **readelf -S hello** и внимательно изучаем вывод. 

Обращаем внимание на колонки Offset (смещение секции от начала файла) и Size (размер секции в байтах).

<img src="https://github.com/linafillippova/articles/blob/main/screens25-04-14/2.png"> 

<img src="https://github.com/linafillippova/articles/blob/main/screens25-04-14/3.png"> 

Здесь мы видим, что .comment заканчивается на: 0x3018 + 0x1f = 0x3037, а
.symtab начинается на: 0x3038

Разница: 0x3038 - 0x3037 = 0x1 (1 байт padding - очень мало).

Так как места у нас мало мы запишем символ “A” (0x41) в этот 1-байтный padding.

Откроем файл hello в hex-редакторе.

Перейдем к смещению 0x3037(в редакторе hexedit можно нажать ctlr+g и ввести смещение).

<img src="https://github.com/linafillippova/articles/blob/main/screens25-04-14/4.png"> 

Заменяем байт по этому смещению на 0x41 (шестнадцатеричное представление символа “A”).

<img src="https://github.com/linafillippova/articles/blob/main/screens25-04-14/5.png"> 

Итак, мы смогли спрятать одну букву, при этом не поломав сам файл (то есть скрипт должен запускаться).

**Важно:** Компоновщик (linker) может располагать секции по-разному в зависимости от настроек компиляции, оптимизации и других факторов. Поэтому всегда проверяем вывод readelf -S для конкретного файла.


## 3. Обнаружение данных в Padding 

Итак, мы спрятали сообщение в padding. Но как его найти? 

**3.1 Простой анализ секций**

Первым делом, снова используем **readelf -S hello** и анализируем вывод. Ищем места, где может быть padding. Сравниваем смещения и размеры секций, как мы это делали раньше. 

**3.2 Ручной анализ с помощью hex-редактора**

Основной инструмент для обнаружения скрытых данных в padding - это наши глаза и hex-редактор.

1.	Открываем файл hello в hex-редакторе.

2.	Переходим по смещению, где, по нашему мнению, находится padding. В нашем примере это 0x3037.

Что мы ищем?

•	ASCII-строки: Самый простой случай - если в padding записана обычная текстовая строка (как в нашем примере). Мы увидим читаемые символы в hex-редакторе.

•	Необычные данные: Даже если данные зашифрованы или сжаты, они могут выделяться на фоне нулевых байтов, которыми обычно заполнен padding.

•	Сигнатуры известных форматов: Если в padding спрятан другой файл (например, ZIP-архив или изображение), мы можем увидеть сигнатуру этого формата (например, PK для ZIP).

В нашем примере, если мы перейдем по смещению 0x3037, мы должны увидеть символ “А”. Это довольно очевидно, поэтому такой метод стеганографии считается слабым.

<img src="https://github.com/linafillippova/articles/blob/main/screens25-04-14/6.png">

**3.3 Анализ энтропии**

Анализ энтропии - это более продвинутый метод, который может помочь выявить наличие скрытых данных, даже если они зашифрованы или сжаты.

Энтропия - это мера случайности данных. Области файла с высокой энтропией (близкой к 8) содержат более случайные данные, чем области с низкой энтропией (близкой к 0). 

Шифрованные и сжатые данные обычно имеют высокую энтропию.

Мы можем использовать инструмент binwalk для анализа энтропии ELF-файла. Запустите команду:

**binwalk -E hello**

**binwalk** построит график энтропии файла. Если в области padding находится зашифрованная или сжатая информация, мы увидим всплеск энтропии в этой области.

<img src="https://github.com/linafillippova/articles/blob/main/screens25-04-14/7.png">

**Важно:** Высокая энтропия не всегда означает, что в файле есть скрытые данные. Это может быть просто особенность программы. Однако это повод для более тщательного анализа.


**3.4 Что делать, если данные зашифрованы?**

Если мы обнаружили подозрительные данные в padding, но они выглядят как случайный набор байтов, это может означать, что они зашифрованы. В этом случае нам нужно попытаться дешифровать данные. 

Для этого нам может понадобиться:

•	Ключ шифрования: Если программа использует какой-то ключ для шифрования данных, нам нужно его найти. Ключ может быть жестко закодирован в программе, получен из пользовательского ввода или сгенерирован каким-то алгоритмом.

•	Алгоритм шифрования: Нам нужно знать, какой алгоритм шифрования используется (например, AES, DES, RC4).


## 4. Автоматизация процесса 

Автоматизация может значительно ускорить процесс поиска padding и извлечения скрытых данных, особенно если у нас много файлов для анализа.

**4.1 Что такое LIEF?**

LIEF (LIEF - Library to Instrument Executable Formats) - это кроссплатформенная библиотека для анализа, модификации и абстракции исполняемых форматов (PE, ELF, Mach-O). 

Она позволяет легко получать доступ к различным элементам структуры исполняемых файлов, включая секции, заголовки и т.д.

Установка **LIEF**:

**pip install lief**

**4.2 Пример скрипта на Python для поиска Padding и извлечения данных:**

```python
import lief

def find_padding(file_path):
    """
    Находит области padding в ELF-файле и пытается извлечь из них данные.
    """
    try:
        binary = lief.parse(file_path)
        if binary is None:
            print(f"Ошибка: Не удалось распарсить файл {file_path}")
            return

        print(f"Анализ файла: {file_path}")

        sections = binary.sections
        for i in range(len(sections) - 1):
            current_section = sections[i]
            next_section = sections[i+1]

            padding_size = next_section.offset - (current_section.offset + current_section.size)

            if padding_size > 0:
                print(f"  Padding найдено между секциями {current_section.name} и {next_section.name}")
                print(f"    Смещение: 0x{current_section.offset + current_section.size:x}")
                print(f"    Размер: 0x{padding_size:x} байт")

                # Попытка извлечь ASCII-строку из padding
                with open(file_path, "rb") as f:
                    f.seek(current_section.offset + current_section.size)
                    padding_data = f.read(padding_size)
                    try:
                        decoded_string = padding_data.decode("ascii")
                        print(f"    Возможная ASCII-строка: {decoded_string.strip()}") # strip() убирает лишние пробелы
                    except UnicodeDecodeError:
                        print("    Не удалось декодировать как ASCII")


    except lief.lief_errors.bad_file as e:
        print(f"Ошибка при обработке файла: {e}")
```

Что делает этот скрипт:

1.	Импортирует библиотеку lief.

2.	Определяет функцию find_padding(file_path), которая принимает путь к ELF-файлу в качестве аргумента.

3.	Парсит ELF-файл с помощью lief.parse(file_path).

4.	Перебирает все секции в файле.

5.	Для каждой пары соседних секций вычисляет размер padding между ними.

6.	Если размер padding больше 0, выводит информацию о смещении и размере padding.

7.	Пытается прочитать данные из области padding и декодировать их как ASCII-строку.


## 5. Контрмеры 

Как усложнить обнаружение стеганографии в padding?

•	Шифрование данных перед сокрытием: Это сделает невозможным чтение данных, если не известен ключ шифрования.

•	Сжатие данных перед сокрытием: Это уменьшит размер данных и увеличит их энтропию, что затруднит обнаружение.

•	Разбрасывание данных по разным областям padding: Вместо того, чтобы записывать все данные в одну область padding, их можно разбить на части и разбросать по разным местам в файле.
