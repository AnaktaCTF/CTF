# Privilege Escalation в CTF: от рядового пользователя до администратора

Privilege Escalation, или повышение привилегий, представляет собой одну из наиболее распространенных и увлекательных техник, используемых в соревнованиях формата Capture The Flag (CTF). Этот метод позволяет участникам продемонстрировать глубокое понимание принципов информационной безопасности и умение находить уязвимости в системах для получения доступа к защищенным ресурсам. Повышение привилегий часто является ключевым этапом в решении комплексных CTF-задач, позволяя преодолеть ограничения прав доступа и захватить финальный флаг. В данной статье мы рассмотрим сущность этой техники, её методы применения и приведем конкретный пример, демонстрирующий эффективность Privilege Escalation в контексте CTF-соревнований.


## Что такое Privilege Escalation

Privilege Escalation (повышение привилегий) — это использование различных уязвимостей операционной системы и прикладного программного обеспечения для повышения своих полномочий в атакуемой системе. В контексте Linux-систем под повышением привилегий обычно подразумевается получение прав суперпользователя (root) при работе от обычного пользователя. Эта техника является важным элементом многих CTF-заданий, особенно в категориях PWN и admin.

Существует два основных типа эскалации привилегий:

- **Вертикальная** – переход от доступа с обычными привилегиями к доступу с более высокими привилегиями (например, от обычного пользователя к root).
- **Горизонтальная** – переход от одного пользователя с определенными привилегиями к другому пользователю такого же уровня, но который может иметь дополнительные возможности (например, sudo для конкретных команд).


## Технические аспекты Privilege Escalation

Эскалация привилегий – это результат действий, которые позволяют злоумышленнику получить более высокий уровень разрешений в атакуемой системе. Технические аспекты включают:

1. **Уязвимости ядра ОС** – использование известных уязвимостей для получения привилегированного доступа.
2. **Неправильно настроенные разрешения файлов** – файлы с чрезмерными правами доступа или неправильными атрибутами.
3. **SUID/SGID бинарные файлы** – исполняемые файлы, которые запускаются с привилегиями владельца/группы.
4. **Учетные данные, хранящиеся в открытом виде** – пароли в конфигурационных файлах, истории команд и т.д.
5. **Небезопасные конфигурации sudo** – неправильно настроенные права sudo могут привести к эскалации.
6. **Уязвимые сервисы и приложения** – локальные службы с известными уязвимостями.


## Privilege Escalation в CTF соревнованиях

В CTF соревнованиях задачи на повышение привилегий обычно требуют тщательного анализа системы для определения путей эскалации. Флаги (секретная информация, которую нужно найти) часто располагаются в файлах, доступных только привилегированным пользователям.

Ключевой момент – это первоначальное исследование системы (enumeration), которое помогает определить потенциальные векторы атаки. Важно проверить такие аспекты, как:

- Версия ядра системы
- Установленные программы и их версии
- Права пользователей и группы
- Доступные sudo-команды
- Cron-задачи
- Открытые сетевые порты
- Неправильно настроенные файловые разрешения
- Уязвимости в SUID приложениях

Рассмотрим последний пункт чуть подробнее.

## Уязвимости в SUID приложениях

SUID (Set User ID) — это особый режим работы исполняемого файла в Linux, который позволяет запускать программу с правами владельца файла, а не пользователя, который её запускает. Ошибки в SUID приложениях могут помочь с повышением привелегий. Рассмотрим примеры таких ошибок и уязвимостей:

### Недостаточная проверка пользовательского ввода (Input Validation)
Отсутствие строгой проверки вводимых данных позволяет злоумышленнику передавать вредоносные команды или параметры, что ведет к выполнению произвольного кода или чтению защищенных файлов.


### Ошибки при работе с файлами

Если SUID-приложение открывает или записывает файлы без проверки путей или прав доступа, атакующий может использовать это для чтения чувствительных данных (например, `/etc/shadow`) или перезаписи критически важных файлов.

**Типичный сценарий:**

- Приложение с SUID-битом записывает данные в файл без проверки пути.
- Атакующий создает символическую ссылку на важный файл системы.
- В результате приложение перезаписывает этот файл с привилегиями владельца (например, root), что приводит к компрометации системы.


### Переполнение буфера (Buffer Overflow)

Классическая уязвимость, когда приложение не проверяет длину вводимых данных и позволяет перезаписать память за пределами выделенного буфера. В случае SUID-бинарника это особенно критично: злоумышленник может получить контроль над процессом с повышенными привилегиями.


### Неправильная обработка переменных окружения

Некоторые переменные окружения (`LD_PRELOAD`, `LD_LIBRARY_PATH`) по умолчанию игнорируются при запуске SUID-приложений в целях безопасности. Однако ошибки конфигурации или реализации могут привести к тому, что эти ограничения будут сняты или обойдены.


### Использование небезопасных функций

Функции вроде `gets()`, `strcpy()`, `sprintf()` известны своей небезопасностью и могут привести к переполнению буфера и другим проблемам безопасности. Их использование в SUID-программах открывает прямой путь к эксплуатации.


### Неправильное выставление флага SUID

Одной из самых распространенных ошибок является установка бита SUID на программы, которые изначально не предназначены для этого (например, текстовые редакторы). Это позволяет атакующему легко изменять системные файлы с повышенными привилегиями.


### Отсутствие минимальных привилегий (Least Privilege)

Часто владельцем SUID-программ является root, хотя для выполнения конкретной задачи достаточно было бы менее привилегированного пользователя. Это увеличивает риск успешной атаки.


## Инструменты для Privilege Escalation

### 1. LinEnum

LinEnum – один из наиболее популярных скриптов для автоматизированной проверки системы Linux на потенциальные уязвимости повышения привилегий. Он выполняет комплексное сканирование системы и предоставляет подробный отчет о возможных векторах эскалации.

Основные возможности:

- Проверка ядра и установленных пакетов
- Поиск SUID/SGID файлов
- Проверка прав доступа к конфигурационным файлам
- Анализ cron-задач и запущенных процессов
- Поиск слабостей в настройках sudo


### 2. Linux-exploit-suggester

Этот инструмент специализируется на поиске подходящих эксплойтов ядра для текущей версии Linux. После сканирования он предоставляет список потенциально применимых эксплойтов с указанием CVE номеров и ссылок на источники.

Пример использования:

```
./Linux_Exploit_Suggester.pl -k 3.0.0
```

Результат может выглядеть так:

```
Kernel local: 3.0.0
Possible Exploits:
[+] semtex
CVE-2013-2094
Source: http://www.exploit-db.com/download/25444/
[+] memodipper
CVE-2012-0056
Source: http://www.exploit-db.com/exploits/18411/
```


### 3. PXEnum

PXEnum – мощный скрипт, основная задача которого – функция перечисления (enumeration) системы. Он собирает всю доступную информацию о системе, что критически важно для определения путей эскалации.

Возможности инструмента:

- Извлечение хешей паролей
- Получение содержимого директорий
- Сбор подробных сведений о системе
- Обнаружение application-серверов и приложений
- Анализ сетевых соединений и пользователей

Для запуска не требуются права root:

```
$ wget https://raw.githubusercontent.com/shawnduong/PXEnum/master/PXEnume.sh
$ chmod +x PXEnum.sh
$ bash PXEnum.sh
```


### 4. MIDA Multitool

MIDA Multitool – комплексный инструмент, созданный на базе менее популярных утилит SysEnum и RootHelper. Он объединяет возможности различных инструментов, предоставляя больше функциональности.

Основные компоненты:

- **SysEnum** – получение основной информации о системе
- **RootHelper** – помощь в эскалации привилегий
- Дополнительные модули для комплексного анализа и эксплуатации

Этот инструмент особенно полезен в сложных CTF заданиях, где требуются различные подходы к эскалации привилегий.

### 5. Unix-privesc-check

Unix-privesc-check – скрипт, который проверяет неправильные конфигурации, потенциально позволяющие локальным непривилегированным пользователям повысить привилегии. Работает на различных Unix-системах, включая Linux, Solaris, HPUX и FreeBSD.

Преимущество этого инструмента – он написан как единый shell-скрипт, что упрощает его загрузку и запуск:

```
$ ./unix-privesc-check > output.txt
```

Скрипт проверяет разрешения файлов и другие настройки, которые могут позволить локальным пользователям повысить привилегии. В выводе следует искать слово 'WARNING', указывающее на потенциальные проблемы.

### 6. LinuxPrivChecker

LinuxPrivChecker – мощный инструмент, который автоматизирует процесс поиска путей эскалации привилегий. Он выполняет систематическую проверку системы на наличие уязвимостей и предоставляет подробный отчет.

Возможности:

- Проверка версии ядра на известные уязвимости
- Поиск файлов с небезопасными разрешениями
- Анализ конфигураций пользователей и групп
- Проверка исполняемых файлов с установленным SUID/SGID битом
- Выявление ненадежных путей в переменной PATH


## Пример применения Privilege Escalation в CTF

Рассмотрим задание ["RootMe"](https://tryhackme.com/room/rrootme) с сайта "TryHackMe".

Для начала проведём сканирование портов машины:
![priv_esc_0](https://github.com/user-attachments/assets/3fac7b14-b3ec-49ec-8a46-7bdb85202789)

Видим открытый 80 порт с http сервисом. На самом сайте нет ничего интересного, поэтому с помощью инструмента GoBuster попробуем перебрать директории.
![priv_esc_1](https://github.com/user-attachments/assets/049e6ecc-cb11-480e-957c-1d758fa6f446)

Из необычного, видим директории "/panel" и "/uploads", переходим на "/panel" и видим предложение загрузки файла. Загрузим файл с [php-reverce-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) (примечание: файл с расширением .php загрузить не даёт, поэтому меняем расширение на .php5 или .phttp)
![priv_esc_2](https://github.com/user-attachments/assets/d8049a89-95aa-484a-a200-395904dea575)
![priv_esc_3](https://github.com/user-attachments/assets/f859ef4c-9449-443d-92ea-222bc238c0a2)

После успешной загрузки нашего файла, мы можем увидеть его в директории "/uploads":
![priv_esc_4](https://github.com/user-attachments/assets/93f7c113-eda2-4eec-8bb4-d576d205b376)

Ставим Listener на порт, указанный в скрипте. Если всё прошло успешно, то мы получаем доступ к shell.
![priv_esc_5](https://github.com/user-attachments/assets/ac1bffe6-0390-4327-93ad-dcf78c43eed9)

Попытаемся повысить свои привилегии. С помощью команды "find / -perm -u=s 2>/dev/null" ищем файлы с SUID разрешениями.
![priv_esc_6](https://github.com/user-attachments/assets/480da26d-2248-4245-a843-5ce43a974a7b)

По какой то причине, файл /usr/bin/python имеет эти разрешения, нам же лучше. С помощью команды "./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'", взятой с [GTFOBins](https://gtfobins.github.io/gtfobins/python/#suid), становимся root пользователем. Флаг для root можно найти по директории "/root". Задание выполнено.
![priv_esc_7](https://github.com/user-attachments/assets/c469a5d2-dd11-48a2-b78f-abb545d17c37)


## Заключение

Privilege Escalation является важным и часто встречающимся компонентом CTF-заданий, требующим от участников глубокого понимания принципов информационной безопасности и умения находить и эксплуатировать уязвимости в системах. Владение техниками повышения привилегий не только помогает успешно решать задания на CTF-соревнованиях, но и формирует ценные навыки для работы в области информационной безопасности. Использование различных методов Privilege Escalation, от эксплуатации ошибок конфигурации до применения сложных технических уязвимостей, делает этот аспект CTF-соревнований особенно интересным и познавательным для участников всех уровней подготовки.
