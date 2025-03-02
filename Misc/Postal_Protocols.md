# Тестирование почтовых протоколов SMTP, POP3, IMAP

## Введение

Электронная почта — важный инструмент связи, который широко используется в современном мире. Однако, как и любая другая технология, протоколы, обеспечивающие её работу, могут иметь уязвимости. Эти уязвимости часто используются злоумышленниками для атак, поэтому изучение, тестирование и защита этих протоколов имеет ключевое значение, особенно в контексте информационной безопасности и CTF (Capture The Flag) задач.
![image](https://github.com/user-attachments/assets/6372a55c-5a6e-4b08-a4e8-ff3ff963ec7b)


---


## 1. Описание почтовых протоколов

### SMTP (Simple Mail Transfer Protocol)

SMTP — это протокол, используемый для отправки электронной почты. Он работает на уровне приложения и использует TCP порт 25 (или 587 для защищённых соединений).
![image](https://github.com/user-attachments/assets/01c1322b-2299-4465-a3c6-2ee658b09305)


**Ключевые особенности:**

- Основной протокол для передачи почты между серверами.
- Возможность добавления расширений (например, SMTP AUTH для аутентификации).
- Использует простой текст для команд и сообщений.

### Подключение
#### Подключение через Telnet
Telnet можно использовать для подключения к удалённому серверу с помощью команды:

```bash
telnet example.com 25
```

### Перечисление
#### Определение SMTP-сервера
Для проверки наличия SMTP-сервера на целевом хосте можно использовать Nmap:

```bash
nmap -p25,465,587 -sV -Pn target.com
```

#### Перечисление пользователей
Nmap имеет скрипт для перечисления пользователей SMTP:

```bash
nmap -p25 --script smtp-enum-users.nse target.com
```

#### Перечисление записей DNS MX
Для нахождения почтовых серверов (MX) домена можно использовать утилиту dig:

```bash
dig +short mx example.com
```

#### Раскрытие информации с NTLM-аутентификацией
Некоторые SMTP-серверы с включённой NTLM-аутентификацией могут раскрывать конфиденциальную информацию, например версию Windows Server и внутренний IP:

```bash
nmap -p25 --script smtp-ntlm-info --script-args smtp-ntlm-info.fingerprint=on target.com
```

### Вектор атак
#### Уязвимость Open Relay
Open Relay позволяет серверу принимать и пересылать сообщения, не предназначенные для локальных пользователей. Для проверки:

```bash
telnet target.com 25
MAIL FROM:<test@example.com>
RCPT TO:<test2@anotherexample.com>
DATA
Subject: Test open relay
Test message
.
QUIT
```

### Постэксплуатация
#### Общие команды SMTP
| Команда   | Описание                                  | Пример                |
|-----------|------------------------------------------|-----------------------|
| HELO      | Идентифицирует клиента серверу.          | `HELO example.com`    |
| EHLO      | Расширенное приветствие.                 | `EHLO example.com`    |
| MAIL FROM:| Указывает адрес отправителя.             | `MAIL FROM:<sender@example.com>` |
| RCPT TO:  | Указывает адрес получателя.              | `RCPT TO:<recipient@example.com>` |
| DATA      | Начало тела сообщения.                   | `DATA`                |
| RSET      | Сбрасывает сессию.                       | `RSET`                |
| NOOP      | Без операции, используется для тестирования. | `NOOP`                |
| QUIT      | Завершает сессию.                        | `QUIT`                |

---



### POP3 (Post Office Protocol v3)

POP3 — это протокол для получения электронной почты с сервера. Работает на порту 110 (или 995 для SSL/TLS).
![image](https://github.com/user-attachments/assets/01a21c31-0d14-4179-894d-13f927a53aff)


**Ключевые особенности:**

- Предназначен для загрузки писем с сервера на локальное устройство.
- Удаляет письма с сервера после загрузки (по умолчанию).
- Ограниченная функциональность (нет синхронизации между устройствами).


### Подключение
#### Ручное подключение
Для подключения можно использовать Netcat:

```bash
nc <target-ip> 110
```

#### Подключение через OpenSSL
Для тестирования защищённого соединения POP3:

```bash
openssl s_client -connect <ip>:995
```

### Распознавание
#### Сбор баннеров
Для получения баннера:

```bash
nc <target-ip> 110
```

#### Получение информации через Nmap
```bash
nmap -p 110 --script pop3-capabilities <ip>
```

### Перечисление
Использование скрипта для сбора информации:

```bash
nmap -p 110 --script pop3-ntlm-info <ip>
```

### Вектор атак
#### Брутфорс
##### Nmap
```bash
nmap -p 110 --script pop3-brute --script-args userdb=users.txt,passdb=pass.txt <ip>
```

##### Hydra
```bash
hydra -L <user list file> -P <password list file> -f <ip> pop3 -V
```

### Постэксплуатация
#### Извлечение писем
Для чтения писем используйте команду:

```bash
RETR 1
```

#### Удаление писем
Для удаления письма:

```bash
DELE 1
```

#### Проверка на наличие учётных данных
Изучите содержимое писем на наличие логинов и паролей.

#### Поиск конфиденциальных данных
В письмах могут содержаться личные, финансовые или корпоративные секреты.

**Примеры команд POP3:**
- USER — указание имени пользователя.
- PASS — ввод пароля.
- LIST — список сообщений.
- RETR — получение сообщения.
- DELE — удаление сообщения.

---


### IMAP (Internet Message Access Protocol)

IMAP — это протокол для доступа к электронной почте, который работает на порту 143 (или 993 для SSL/TLS).
![image](https://github.com/user-attachments/assets/939f7e93-dd46-4269-a1f3-cd97882da88a)

**Ключевые особенности:**

- Поддержка работы с почтой на сервере без необходимости её загрузки.
- Возможность работы с папками, поиска и фильтрации сообщений.
- Синхронизация между устройствами.

#### Подключение
##### Подключение через Telnet
Для подключения к серверу IMAP используйте:

```bash
telnet <server-ip> <port>
```

##### Подключение через почтовые клиенты
Для работы с IMAP можно использовать почтовые клиенты, такие как Outlook, Thunderbird или Apple Mail.

#### Распознавание
##### Определение IMAP-сервера
Сканирование с помощью Nmap:

```bash
nmap -p 143,993 <target-ip>
```

##### Сбор баннеров
Получение баннера с помощью Telnet:

```bash
telnet <server-ip> <port>
```

#### Перечисление
##### Перечисление почтовых ящиков
Для получения списка почтовых ящиков:

```bash
LIST "" *
```

##### Перечисление заголовков писем
Получение заголовков письма:

```bash
FETCH 1 BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)]
```

#### Вектор атак
##### Брутфорс
###### Hydra
```bash
hydra -L users.txt -P passwords.txt imap://<server-ip>
```

##### Nmap
```bash
nmap --script imap-brute -p 143,993 <target-ip>
```

##### IMAP-инъекции
Используются для эксплуатации уязвимостей серверного ПО.

##### Атаки «человек посередине» (MitM)
MitM-атаки на IMAP-трафик могут перехватывать и модифицировать сообщения.

#### Постэксплуатация
##### Извлечение почты
После получения доступа к аккаунту можно извлечь конфиденциальную информацию.

##### Манипуляции с письмами
Удаление, пересылка или изменение писем для достижения целей.

##### Настройка переадресации
Установка правил пересылки для отправки входящих сообщений на сторонний адрес.


**Примеры команд IMAP:**
- LOGIN — аутентификация пользователя.
- SELECT — выбор почтового ящика.
- FETCH — получение сообщений.
- STORE — изменение флагов сообщений.
- LOGOUT — завершение сеанса.                                                                                                                                                                   

---

### Другие протоколы

- **MIME (Multipurpose Internet Mail Extensions)** — стандарт для передачи мультимедийных сообщений.
- **ESMTP (Extended SMTP)** — расширение для SMTP, добавляющее поддержку дополнительных функций (например, авторизация).
- **LMTP (Local Mail Transfer Protocol)** — оптимизированный протокол для локальных серверов.

---

## 2. Уязвимости почтовых протоколов

### Общие уязвимости

1. **Проблемы с аутентификацией:**
   - Отсутствие обязательного использования шифрования (например, отправка паролей в открытом виде).
   - Устаревшие методы авторизации (PLAIN, LOGIN).

2. **Man-in-the-Middle (MITM) атаки:**
   - Возможность перехвата данных при отсутствии шифрования (SMTP без STARTTLS, IMAP/POP3 без SSL/TLS).

3. **Ошибки в конфигурации серверов:**
   - Открытые релееры SMTP (Open Relay), позволяющие отправлять спам.
   - Неправильное управление доступом к почтовым ящикам.

4. **Атаки на протоколы:**
   - Командные инъекции (например, подмена команды HELO).
   - Эксплуатация переполнения буфера.

5. **Социальная инженерия и фишинг:**
   - Использование фальсифицированных заголовков в письмах.
   - Отправка поддельных сообщений с легитимных серверов через плохо настроенные SMTP.
    
6. **Подбор паролей через слабую защиту от брутфорса**

### Cпецифичные уязвимости протоколов

- **SMTP:**
  - Подмена отправителя (Email Spoofing) - Отсутствие проверки подлинности отправителя позволяет злоумышленникам отправлять письма от имени доверенных лиц.
  - Открытые релееры (Open Relay) - Серверы, неправильно настроенные для проверки отправителя, позволяют пересылать почту от любого отправителя к любому получателю, что используется для спама и фишинга.

- **POP3:**
  - Перехват учетных данных при отсутствии SSL/TLS.

- **IMAP:**
  - Уязвимости в серверах IMAP, позволяющие выполнение произвольного кода.
  - IMAP-инъекции - Внедрение вредоносных команд через специально сформированные запросы может привести к несанкционированному доступу или утечке данных

---

## 3. Задачи в CTF

### SMTP

1. **Email Spoofing:**
   - Найти и использовать открытую SMTP-конфигурацию для отправки поддельных писем.
   - Подделать заголовки письма для обхода фильтров.

2. **Анализ SMTP трафика:**
   - Исследовать перехваченный дамп трафика, чтобы извлечь данные (учетные записи, команды).

### POP3

1. **Перехват учетных данных:**
   - Декодировать логины и пароли, переданные в незашифрованном виде.
   - Анализировать данные для восстановления писем.

2. **Извлечение вложений:**
   - Восстановить файл, переданный через MIME.

### IMAP

1. **Синхронизация писем:**
   - Выполнить аутентификацию и получить доступ к почтовым ящикам.

2. **Брутфорс:**
   - Найти учетные данные для доступа к серверу.

### Примеры задач

- Найти пароль в заголовках письма.
- Извлечь флаг, скрытый в закодированном содержимом письма (Base64, quoted-printable).
- Перехватить и декодировать данные протоколов.

---

## 4. Как готовиться и решать задачи

### Инструменты для тестирования

1. **Wireshark:**
   - Анализ трафика SMTP, POP3, IMAP.
   - Фильтрация по портам и декодирование содержимого.

2. **Telnet и Netcat:**
   - Ручное тестирование SMTP, POP3, IMAP.
   - Отправка и получение сообщений.

3. **Python скрипты:**
   - Использование библиотек `smtplib`, `imaplib`, `poplib` для автоматизации работы.

4. **Burp Suite:**
   - Перехват HTTPS трафика почтовых клиентов.

5. **Nmap:**
   - Сканирование портов и выполнение скриптов для обнаружения уязвимостей в почтовых сервисах.

6. **Hydra:**
   - Инструмент для проведения брутфорс-атак на почтовые сервисы.

## 5. Pentest SMTP, IMAP, POP3

### Пентест SMTP-сервера

Команда EXPN раскрывает реальные адреса псевдонимов пользователей и списков рассылки, а VRFY может подтвердить существование имён действительных пользователей.

Перечисление через SMTP можно выполнить вручную с помощью таких утилит, как `telnet` и `netcat`, или автоматически, используя различные инструменты, такие как `metasploit`, `nmap` и `smtp-user-enum`. На следующих двух скриншотах показано, как можно перечислять пользователей с помощью команд VRFY и RCPT через службу Telnet.

#### Перечисление пользователей SMTP через Telnet

![image](https://github.com/user-attachments/assets/0e607c60-85c6-4257-a340-14c9eaaecf6c)

#### Перечисление пользователей с помощью команды RCPT
![image](https://github.com/user-attachments/assets/9fd3f607-e1ff-40e5-aadb-552d1282b0d3)

---

#### Metasploit

Модуль, который может выполнять перечисление пользователей через SMTP в Metasploit Framework:

```
auxiliary/scanner/smtp/smtp_enum
```

Единственное, что требуется этому модулю, — это указать IP-адрес удалённого хоста и выполнить команду `run`, так как остальные параметры автоматически заполняются Metasploit.

##### Конфигурация модуля Metasploit для перечисления SMTP
![image](https://github.com/user-attachments/assets/ad8a389e-7130-4a89-8bce-e682ea8cdf5f)


Результаты работы Metasploit показаны на следующем изображении:

##### Результаты перечисления пользователей через Metasploit
![image](https://github.com/user-attachments/assets/6cb82250-35b5-4531-8421-e478b3e15d33)


---

#### smtp-user-enum

Ещё один инструмент, который можно использовать, — это `smtp-user-enum`, предоставляющий три метода перечисления пользователей. Команды, используемые этим инструментом для проверки имён пользователей: `EXPN`, `VRFY` и `RCPT`. Он также поддерживает проверку одного имени пользователя или нескольких через `.txt`-файл. Чтобы эффективно использовать этот инструмент, вам понадобится хороший список имён пользователей. Пример сканирования с использованием команды VRFY, который обнаружил следующие имена пользователей:

##### Перечисление пользователей SMTP с помощью smtp-user-enum
![image](https://github.com/user-attachments/assets/144fd3fe-0893-42e6-9649-edb9df53ee65)


Инструмент также может использоваться для обнаружения действительных email-адресов вместо имён пользователей. Следующее изображение иллюстрирует это использование:

##### Обнаружение email-адресов через smtp-user-enum
![image](https://github.com/user-attachments/assets/985b5325-e714-4b22-9c79-b8eace24704b)


---

#### Nmap

Перечисление SMTP также можно выполнить с помощью Nmap. В движке NSE (Nmap Scripting Engine) есть скрипт для перечисления пользователей SMTP. Основное использование скрипта выглядит так:

```
nmap –script smtp-enum-users.nse 172.16.212.133
```

##### Перечисление имён пользователей SMTP через Nmap
![image](https://github.com/user-attachments/assets/ea390a32-7cdc-40d0-aa45-84574507cda5)

На приведённом изображении видно, что перечисление в этом случае не удалось.

---

#### Вывод

SMTP — это общая служба, которая встречается в каждой сети. Администраторам необходимо правильно настраивать почтовые серверы, запрещая выполнение команд `EXPN`, `VRFY` и `RCPT`, чтобы избежать утечки данных. С другой стороны, тестировщики на проникновение могут использовать имена пользователей, полученные через перечисление, для проведения дальнейших атак на другие системы.

Вот перевод и форматирование секций для IMAP и POP3:

---

### Лучшие практики пентеста IMAP

#### IMAP
IMAP обычно использует порты 143 и 993.

---

```
PORT     STATE SERVICE               VERSION
143/tcp  open  imap                  Dovecot imapd (Ubuntu)
```

---

#### Пентест IMAP

##### Поиск с помощью Shodan:
```
port:143, 993  
port:143 CAPABILITY  
port:993 CAPABILITY  
```

##### Захват баннеров:
```bash
# Захват баннеров и тест соединения
nc -nv IP 143
A1 LOGIN “root” “”
A1 LOGIN root toor
A1 LOGIN root root
```

##### Примеры команд Nmap:
```bash
nmap -p143 -sV --script=banner 192.168.x.x
nmap -p143 --script=imap-ntlm-info 192.168.x.x
msf > use auxiliary/scanner/imap/imap_version
openssl s_client -connect 192.168.x.x:993 -quiet
telnet 192.168.x.x 143
```
![image](https://github.com/user-attachments/assets/2b62a4d7-a6a1-4f6f-aa12-c1196b8efbe0)
![image](https://github.com/user-attachments/assets/386a06ae-6d18-433e-90dd-e89e3f993da4)

##### Определение возможностей сервера:
```bash
nmap -sV --script=imap-capabilities -p143 10.10.x.x
```
![image](https://github.com/user-attachments/assets/957aa9e4-9744-4c57-9067-08552d3c291d)

---

#### Захват трафика IMAP
```bash
msf > use auxiliary/server/capture/imap
```

---

#### NTLM-аутентификация — Утечка информации

Если сервер поддерживает NTLM-аутентификацию (Windows), можно получить чувствительную информацию, такую как версия ПО:

```bash
telnet example.com 143
* OK The Microsoft Exchange IMAP4 service is ready.
>> a1 AUTHENTICATE NTLM
+
>> TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
+
TlRMTVNTUAACAAAACgAKADgAAAAFgooCBqqVKFrKPCMAAAAAAAAAAEgASABCAAAABgOAJQAAAA9JAEkAUwAwADEAAgAKAEkASQBTADAAMQABAAoASQBJAFMAMAAxAAQACgBJAEkAUwAwADEAAwAKAEkASQBTADAAMQAHAAgAHwMI0VPy1QEAAAAA
```

Автоматизация через скрипт Nmap:
```bash
nmap --script=imap-ntlm-info.nse
```

---

#### Брутфорс IMAP
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f 192.168.x.x imap -V
```
![image](https://github.com/user-attachments/assets/b85f0c5a-aa75-49b9-9e7e-44bb89770518)

---

#### Использование CURL
Основные команды для работы с IMAP через CURL:
```bash
# Список почтовых ящиков
curl -k 'imaps://10.10.x.x/' --user user:pass

# Список сообщений в папке (например, INBOX)
curl -k 'imaps://10.10.x.x/INBOX?ALL' --user user:pass

# Загрузка сообщения
curl -k 'imaps://10.10.x.x/INBOX;MAILINDEX=1' --user user:pass
```

---

#### Уязвимости IMAP
Примеры:
- **Eudora Qualcomm WorldMail 3.0 [CVE-2005-4267]**
  ```bash
  msf > use exploit/windows/imap/eudora_list
  ```
- **IMAP Fuzzer**
  ```bash
  msf > use auxiliary/dos/windows/imap/fuzz_imap
  ```

---

### Лучшие практики пентеста POP3

#### POP3
POP3 обычно использует порты 110 и 995.

---

#### Что такое POP3?

POP3 (Post Office Protocol) позволяет скачивать письма на локальное устройство, после чего они обычно удаляются с почтового сервера. Это означает, что письма привязаны к конкретному устройству и недоступны для других клиентов после загрузки.

```
PORT     STATE SERVICE               VERSION
110/tcp  open  pop3                  Zimbra Collabration Suite pop3d
```

---

#### Пентест POP3

##### Поиск с помощью Shodan:
```
port:110, 995
```

##### Захват баннеров:
```bash
telnet 10.10.x.x 110
nc -nv 10.10.x.x 110
nmap -p110 --script=banner 10.10.x.x
```
![image](https://github.com/user-attachments/assets/4197e8cf-3a33-405a-bed5-447033451b6f)


##### Определение возможностей POP3:
```bash
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -port 110 192.168.x.x
```
![image](https://github.com/user-attachments/assets/497fa1ac-e503-4144-8be2-fe112e8e5646)

![image](https://github.com/user-attachments/assets/3169c519-7ea3-4f15-a254-5f2b02c7defb)


---

#### Перехват трафика POP3
```bash
msf > use auxiliary/server/capture/pop3
```

---

#### Брутфорс POP3
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```

---

#### Уязвимости POP3
Примеры:
- **Seattle Lab Mail 5.5 [CVE-2003-0264]**
  ```bash
  msf > use exploit/windows/pop3/seattlelab_pass
  ```
- **Cyrus – Gentoo 2006.0 Linux 2.6 [CVE-2006-2502]**
  ```bash
  msf > use exploit/linux/pop3/cyrus_pop3d_popsubfolders
  ```


### Практика

1. **Настройка тестового окружения:**
   - Поднять локальный SMTP, POP3, IMAP-серверы (например, с использованием Docker).
   - Настроить уязвимости (открытые релееры, отсутствие SSL/TLS).

2. **Решение задач:**
   - Начать с анализа сетевого трафика.
   - Понять структуру команд протоколов.
   - Использовать команды протоколов для взаимодействия с сервером (например, `EXAMINE` и `FETCH` в IMAP).

3. **Тренировка на CTF-платформах:**
   - Попробовать задачи на HackTheBox, TryHackMe, CTFLearn, OverTheWire.
   - Решить сценарии, связанные с почтовыми протоколами.

### Пример разбора задачи

1. **Условие:** Имеется дамп трафика, перехваченного с почтового сервера. Найти флаг.
2. **Решение:**
   - Открыть дамп в Wireshark, отфильтровать трафик по порту (25, 110, 143).
   - Декодировать Base64 содержимое письма.
   - Найти флаг в теле или заголовках сообщения.

---

## Заключение

Почтовые протоколы остаются важным элементом инфраструктуры, а их уязвимости — частой целью атак. Знание тонкостей работы SMTP, POP3 и IMAP, а также их уязвимостей, позволяет не только улучшить безопасность систем, но и успешно решать задачи на CTF. Постоянная практика, анализ трафика и изучение реальных уязвимостей помогут углубить знания и подготовиться к соревнованиям.

---

## Список источников

1. RFC 5321 - Simple Mail Transfer Protocol (SMTP): https://datatracker.ietf.org/doc/html/rfc5321
2. RFC 1939 - Post Office Protocol - Version 3 (POP3): https://datatracker.ietf.org/doc/html/rfc1939
3. RFC 3501 - Internet Message Access Protocol (IMAP): https://datatracker.ietf.org/doc/html/rfc3501
4. Wireshark Documentation: https://www.wireshark.org/docs/
5. HackTheBox Academy - Protocol Analysis: https://academy.hackthebox.com
6. OverTheWire - Wargames: https://overthewire.org/wargames
7. Practical Ethical Hacking by TCM Security: https://tcm-sec.com
8. https://hackviser.com/tactics/pentesting/services/imap
9. https://hackviser.com/tactics/pentesting/services/smtp
10. https://hackviser.com/tactics/pentesting/services/pop3
11. https://luemmelsec.github.io/Pentest-Everything-SMTP/
12. https://shahmeeramir.com/penetration-testing-an-smtp-server-cf91e4846101
13. https://secybr.com/posts/imap-pentesting-best-practices/
14. https://secybr.com/posts/pop3-pentesting-best-practices/
15. https://helladmin.gitbooks.io/pentesting-handbook/content/phase-2-scanning/service-enumeration/25-tcp-simple-mail-transfer-protocol-smtp.html
16. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection
17. https://docs.cobalt.io/methodologies/external-network/
18. https://csbygb.gitbook.io/pentips/networking-protocols-and-network-pentest/imap
19. https://csbygb.gitbook.io/pentips/networking-protocols-and-network-pentest/pop3
20. https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/
21. https://beaglesecurity.com/blog/vulnerability/imap-smtp-injection.html

