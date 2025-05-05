# Уязвимость Path Traversal

## Введение в уязвимость Path Traversal

**Path Traversal** (или **Directory Traversal**) — это уязвимость, которая может серьёзно угрожать безопасности веб-приложений. Она позволяет атакующим манипулировать входными данными (например, параметрами URL или форм), чтобы обойти ограничения доступа к файлам. Это может привести к:

- доступу к конфиденциальным файлам;
- утечке баз данных;
- выполнению произвольного кода (в некоторых случаях).

## Основы работы Path Traversal

Когда веб-приложение получает параметры, указывающие на файл, злоумышленник может изменить путь, чтобы выйти за пределы разрешённой директории. Обычно используются символы вида `../`.

### Пример уязвимости:

Приложение позволяет скачать отчёт:

```
http://example.com/download?file=report.pdf
```

Сервер формирует путь так:

```
/var/www/html/files/report.pdf
```

Атакующий меняет параметр `file`:

```
http://example.com/download?file=../../../../etc/passwd
```

Результат: попытка загрузить системный файл `/etc/passwd`.

## Символы и методы обхода в Path Traversal

Чтобы обойти защиту, используются различные символы и кодировки:

- `../` — переход на уровень выше.
- `../../` — два уровня вверх и т.д.
- `..\..\` — для Windows.
- `%2e%2e%2f` — URL-кодированный вариант `../`.
- `%2e%2e%2c%2e%2e%2f` — комбинированный обход фильтров.
- `/..//` или `\..\..\` — перемешивание слэшей.

### Пример:

```
http://example.com/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## Примеры уязвимости Path Traversal

### Пример 1: Скачивание отчётов

```
http://example.com/download?file=report.pdf
```

Изменение параметра:

```
http://example.com/download?file=../../../../etc/passwd
```

### Пример 2: Загрузка аватара

```
http://example.com/upload?file=user.jpg
```

Изменение:

```
http://example.com/upload?file=../../../../etc/passwd
```

### Пример 3: Отображение изображений

```
http://example.com/images?image=vacation.jpg
```

Изменение:

```
http://example.com/images?image=../../../../etc/shadow
```

### Пример 4: API-доступ к файлам

```
http://example.com/api/download?path=reports/january.pdf
```

Изменение:

```
http://example.com/api/download?path=../../../../etc/passwd
```

## Как искать уязвимость Path Traversal

### 1. Анализ параметров URL

Проверьте параметры:

- `file`, `path`, `image`, `download`, `upload`, `url` и др.

Примеры:

```
http://example.com/download?file=report.pdf
http://example.com/api/file?path=images/vacation.jpg
```

### 2. Манипуляции с параметрами

Пробуйте такие запросы:

```
http://example.com/download?file=../../../../etc/passwd
http://example.com/download?file=../../../etc/shadow
```

### 3. URL-кодирование

Проверьте:

```
http://example.com/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### 4. Автоматизированные инструменты

Используйте:

- Burp Suite
- OWASP ZAP
- Nikto
- DirBuster

## Методы защиты от Path Traversal

### 1. Очистка входных данных

Проверяйте путь на наличие `../`, `..\` и других шаблонов:

```python
import re
if re.search(r'(\.\./|\\\.\.\\)', user_input):
    raise ValueError("Invalid path traversal attempt")
```

### 2. Абсолютные пути

Используйте безопасное соединение путей:

```python
import os
base_dir = '/var/www/html/uploads/'
file_path = os.path.join(base_dir, user_input)
if not file_path.startswith(base_dir):
    raise ValueError("Invalid path traversal attempt")
```

### 3. Безопасные API

В Node.js:

```javascript
const path = require('path');
let safePath = path.resolve(__dirname, 'uploads', user_input);
```

### 4. Ограничение прав доступа

Разрешайте доступ только к конкретным директориям (например, `/uploads/`).

### 5. Логирование и мониторинг

```python
import logging
logging.basicConfig(filename='file_access.log', level=logging.INFO)
logging.info(f"File access attempt: {user_input}")
```

### 6. Белые списки

```python
allowed_files = ['report.pdf', 'image.jpg']
if user_input not in allowed_files:
    raise ValueError("Invalid file access attempt")
```

## Заключение

**Path Traversal** — серьёзная уязвимость, способная привести к утечке данных и компрометации системы. 
