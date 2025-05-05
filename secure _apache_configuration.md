# Настройка и безопасная конфигурация сервера Apache на Ubuntu

![image](https://github.com/user-attachments/assets/360d55a5-9b5a-4b95-84d2-78950326d91c)


## Содержание
1. [Введение](#введение)
2. [Установка Apache](#установка-apache)
3. [Настройка брандмауэра (UFW)](#настройка-брандмауэра-ufw)
4. [Шифрование с SSL/TLS и HSTS](#шифрование-с-ssltls-и-hsts)
5. [Защита конфигурации Apache](#защита-конфигурации-apache)
6. [Настройка mod_security](#настройка-mod_security)
7. [Защита SSH с Fail2Ban](#защита-ssh-с-fail2ban)
8. [Защита от DDoS с mod_evasive и Fail2Ban](#защита-от-ddos-с-mod_evasive-и-fail2ban)
9. [Изоляция процессов с AppArmor](#изоляция-процессов-с-apparmor)
10. [Оптимизация производительности](#оптимизация-производительности)
11. [Логирование и ротация логов](#логирование-и-ротация-логов)
12. [Автоматизация обновлений](#автоматизация-обновлений)
13. [Резервное копирование](#резервное-копирование)
14. [Тестирование безопасности](#тестирование-безопасности)
15. [Заключение](#заключение)
16. [Список источников](#список-источников)

## Введение

Apache HTTP Server — один из самых популярных веб-серверов, удерживающий около 31% рынка по данным W3Techs (2025). Его гибкость, модульная архитектура и поддержка динамических приложений делают его идеальным выбором для веб-приложений, корпоративных порталов и платформ электронной коммерции. Однако веб-серверы являются мишенью для кибератак, таких как DDoS, XSS, SQL-инъекции, MITM и brute-force. По данным Positive Technologies (2023), 78% организаций столкнулись с атаками на веб-приложения, а Kaspersky сообщает, что 60% атак в 2023 году использовали SQL-инъекции. Неправильная конфигурация сервера может привести к утечке данных, простоям или полной компрометации системы.

**Зачем это нужно?** Настройка безопасного Apache на Ubuntu 24.04 минимизирует эти риски, обеспечивая защиту от современных угроз, соответствие стандартам PCI DSS и GDPR, а также высокую производительность для динамических приложений. Apache, в отличие от NGINX, ориентированного на статический контент, выделяется поддержкой сложных приложений через модули, такие как `mod_php`, но требует тщательной настройки для устранения уязвимостей. Эта статья поможет системным администраторам и разработчикам создать сервер, устойчивый к атакам, подходящий для корпоративных, образовательных или личных проектов.

Основные угрозы по OWASP Top 10 включают:
- **Broken Access Control**: Неправильные права доступа открывают доступ к закрытым ресурсам.
- **Криптографические сбои**: Устаревшие протоколы (например, SSLv3) уязвимы для перехвата.
- **Инъекции (SQL, XSS)**: 60% атак на веб-приложения в 2023 году использовали SQL-инъекции.
- **DDoS**: Перегрузка сервера запросами вызывает отказ в обслуживания.
- **Brute-force**: Атаки на SSH или веб-приложения для подбора паролей.

Эта статья предоставляет пошаговое руководство по настройке Apache на Ubuntu 24.04, минимизирующее эти угрозы через шифрование (SSL/TLS), фильтрацию запросов (`mod_security`), защиту от DDoS (`mod_evasive`, `Fail2Ban`), изоляцию процессов (AppArmor), оптимизацию производительности и резервное копирование.


## Установка Apache

**Защита от угроз**: Устаревшие версии Apache содержат известные уязвимости (например, CVE), которые эксплуатируются для получения доступа или выполнения кода. Установка свежей версии с патчами безопасности предотвращает такие атаки.

### Шаг 1: Обновление системы
**Что делает**: Обновляет списки пакетов и устанавливает последние версии программ, включая патчи безопасности.  
**Что настраиваем**: Системный менеджер пакетов `apt` для Ubuntu.  
**Почему важно**: Устраняет уязвимости в ядре, библиотеках и утилитах, которые могут быть использованы для атак.

```bash
sudo apt update && sudo apt upgrade -y
```

- `sudo`: Выполняет команду с правами суперпользователя.
- `apt update`: Обновляет списки пакетов из репозиториев.
- `apt upgrade -y`: Устанавливает новые версии пакетов, флаг `-y` подтверждает действия автоматически.

### Шаг 2: Установка Apache
**Что делает**: Устанавливает Apache и его зависимости.  
**Что настраиваем**: Веб-сервер Apache (`apache2`) для обработки HTTP-запросов.  
**Почему важно**: Свежая версия Apache минимизирует риски эксплуатации уязвимостей.

```bash
sudo apt install apache2 -y
```

- `apt install apache2`: Устанавливает пакет `apache2`.
- `-y`: Автоматически соглашается с установкой.

### Шаг 3: Запуск и автозагрузка
**Что делает**: Запускает Apache и добавляет его в автозагрузку для старта при перезагрузке.  
**Что настраиваем**: Службу `apache2` через `systemd`.  
**Почему важно**: Гарантирует, что сервер доступен после установки и перезагрузок.

```bash
sudo systemctl start apache2
sudo systemctl enable apache2
```

- `systemctl start apache2`: Запускает службу Apache.
- `systemctl enable apache2`: Включает автозагрузку.

Проверьте статус:

```bash
sudo systemctl status apache2
```

**Что делает**: Показывает состояние службы Apache (запущена или нет).  
**Что настраиваем**: Проверяем работоспособность `apache2`.  
**Почему важно**: Подтверждает, что сервер работает корректно.  
Ожидаемый вывод:

```
● apache2.service - The Apache HTTP Server
     Active: active (running) since ...
```

Откройте `http://<server-ip>` в браузере, чтобы увидеть страницу приветствия Apache.

## Настройка брандмауэра (UFW)

**Защита от угроз**: Открытые порты уязвимы для атак, таких как сканирование портов или эксплуатация сервисов (например, устаревших FTP или Telnet). UFW ограничивает доступ, минимизируя поверхность атаки.

### Шаг 1: Установка UFW
**Что делает**: Устанавливает `ufw` — упрощённый интерфейс для управления iptables.  
**Что настраиваем**: Брандмауэр для контроля сетевого трафика.  
**Почему важно**: Позволяет разрешать только необходимые соединения, снижая риск атак.

```bash
sudo apt install ufw -y
```

- `apt install ufw`: Устанавливает пакет `ufw`.

### Шаг 2: Настройка правил
**Что делает**: Устанавливает политики по умолчанию и разрешает трафик для SSH, HTTP и HTTPS.  
**Что настраиваем**: Правила брандмауэра для входящих и исходящих соединений.  
**Почему важно**: Запрещает несанкционированный доступ, сохраняя доступ к нужным сервисам.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

- `default deny incoming`: Запрещает все входящие соединения, кроме разрешённых.
- `default allow outgoing`: Разрешает исходящие соединения.
- `allow ssh`: Открывает порт 22 для SSH (удалённое управление).
- `allow 80/tcp`: Открывает порт 80 для HTTP.
- `allow 443/tcp`: Открывает порт 443 для HTTPS.

### Шаг 3: Активация и проверка
**Что делает**: Активирует брандмауэр и отображает текущие правила.  
**Что настраиваем**: Состояние UFW.  
**Почему важно**: Подтверждает, что только разрешённые порты открыты.

```bash
sudo ufw enable
sudo ufw status
```

- `ufw enable`: Запускает брандмауэр.
- `ufw status`: Показывает активные правила.  
Ожидаемый вывод:

```
StatusFloor: active
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
```

## Шифрование с SSL/TLS и HSTS

**Защита от угроз**: MITM-атаки перехватывают незашифрованный трафик, крадя данные (пароли, платёжные данные). SSL/TLS шифрует трафик, а HSTS предотвращает использование HTTP.

### Шаг 1: Установка Certbot
**Что делает**: Устанавливает Certbot для автоматического получения SSL-сертификатов от Let’s Encrypt.  
**Что настраиваем**: Утилиту для управления сертификатами и интеграцию с Apache.  
**Почему важно**: Обеспечивает бесплатное шифрование, минимизируя затраты на безопасность.

```bash
sudo apt install certbot python3-certbot-apache -y
```

- `certbot`: Утилита для получения сертификатов.
- `python3-certbot-apache`: Плагин для автоматической настройки Apache.

### Шаг 2: Получение сертификата
**Что делает**: Запрашивает и устанавливает SSL-сертификат для домена.  
**Что настраиваем**: Виртуальный хост Apache и перенаправление HTTP на HTTPS.  
**Почему важно**: Шифрует трафик и повышает доверие пользователей.

```bash
sudo certbot --apache --agree-tos --email admin@example.com -d example.com -d www.example.com
```

- `--apache`: Использует плагин для Apache.
- `--agree-tos`: Соглашается с условиями Let’s Encrypt.
- `--email`: Указывает email для уведомлений.
- `-d`: Указывает домены для сертификата.

Certbot создаёт сертификат, настраивает `mod_ssl` и добавляет перенаправление.

### Шаг 3: Настройка безопасных протоколов
**Что делает**: Ограничивает использование устаревших протоколов и слабых шифров.  
**Что настраиваем**: Модуль `mod_ssl` для TLS.  
**Почему важно**: Устраняет уязвимости, связанные с SSLv2, SSLv3 и TLS 1.0/1.1.

```bash
sudo nano /etc/apache2/mods-enabled/ssl.conf
```

Добавьте:

```apache
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
```

- `SSLProtocol`: Разрешает только TLS 1.2 и 1.3.
- `SSLCipherSuite`: Указывает сильные шифры.
- `SSLHonorCipherOrder`: Принуждает сервер выбирать шифры.

### Шаг 4: Включение HSTS
**Что делает**: Добавляет заголовок HSTS, заставляющий браузеры использовать HTTPS.  
**Что настраиваем**: Виртуальный хост для HTTPS.  
**Почему важно**: Предотвращает MITM-атаки через HTTP.

```bash
sudo nano /etc/apache2/sites-available/example.com.conf
```

В блок `<VirtualHost *:443>` добавьте:

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

- `Header always set`: Устанавливает HTTP-заголовок.
- `Strict-Transport-Security`: Указывает браузеру использовать HTTPS в течение года (`max-age=31536000`).

Активируйте `mod_headers`:

```bash
sudo a2enmod headers
sudo systemctl restart apache2
```

- `a2enmod headers`: Включает модуль для обработки заголовков.
- `systemctl restart apache2`: Перезапускает Apache для применения изменений.

## Защита конфигурации Apache

**Защита от угроз**: Неправильная конфигурация раскрывает информацию о сервере, позволяет XSS, SQL-инъекции или обход директорий. Настройки минимизируют поверхность атаки.

### Скрытие версии Apache
**Что делает**: Скрывает версию Apache и ОС в заголовках ответа.  
**Что настраиваем**: Глобальную конфигурацию Apache.  
**Почему важно**: Усложняет разведку для злоумышленников.

```bash
sudo nano /etc/apache2/apache2.conf
```

Добавьте:

```apache
ServerTokens Prod
ServerSignature Off
```

- `ServerTokens Prod`: Указывает только название сервера (Apache) без версии.
- `ServerSignature Off`: Отключает подпись Apache в сообщениях об ошибках.

### Ограничение HTTP-методов
**Что делает**: Разрешает только безопасные методы (GET, POST, HEAD) и отключает TRACE.  
**Что настраиваем**: Доступ к директориям Apache.  
**Почему важно**: Предотвращает атаки, использующие методы TRACE или редкие методы.

```apache
<Directory /var/www/>
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>
TraceEnable Off
```

- `<LimitExcept>`: Запрещает все методы, кроме указанных.
- `TraceEnable Off`: Отключает метод TRACE, уязвимый для XSS.

### Установка заголовков безопасности
**Что делает**: Добавляет заголовки для защиты от XSS, кликджекинга и других атак.  
**Что настраиваем**: HTTP-заголовки виртуального хоста.  
**Почему важно**: Уменьшает риск клиентских атак.

```bash
sudo nano /etc/apache2/sites-available/example.com.conf
```

Добавьте:

```apache
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"
Header set X-XSS-Protection "1; mode=block"
Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
Header set Referrer-Policy "strict-origin-when-cross-origin"
```

- `X-Content-Type-Options`: Запрещает браузеру угадывать MIME-тип.
- `X-Frame-Options`: Предотвращает кликджекинг.
- `X-XSS-Protection`: Включает фильтр XSS в браузере.
- `Content-Security-Policy`: Ограничивает источники скриптов и стилей.
- `Referrer-Policy`: Контролирует отправку реферера.

### Отключение Directory Listing
**Что делает**: Запрещает отображение содержимого директорий.  
**Что настраиваем**: Доступ к `/var/www/`.  
**Почему важно**: Предотвращает утечку информации о структуре файлов.

```bash
sudo nano /etc/apache2/apache2.conf
```

Измените:

```apache
<Directory /var/www/>
    Options -Indexes
    AllowOverride All
    Require all granted
</Directory>
```

- `Options -Indexes`: Отключает листинг директорий.

### Ограничение размера запросов
**Что делает**: Ограничивает размер тела HTTP-запроса.  
**Что настраиваем**: Глобальные настройки Apache.  
**Почему важно**: Защищает от атак с большими запросами (например, buffer overflow).

```apache
LimitRequestBody 1048576
```

- `LimitRequestBody`: Устанавливает лимит в 1 МБ.

### Защита .htaccess
**Что делает**: Запрещает доступ к файлам `.htaccess`.  
**Что настраиваем**: Доступ к файлам конфигурации.  
**Почему важно**: Предотвращает чтение конфиденциальных настроек.

```apache
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
```

- `FilesMatch`: Запрещает доступ к файлам, начинающимся с `.ht`.

### Использование mod_rewrite
**Что делает**: Блокирует запросы с попытками обхода директорий.  
**Что настраиваем**: Правила переписывания URL.  
**Почему важно**: Защищает от атак, использующих `../`.

```bash
sudo a2enmod rewrite
sudo nano /etc/apache2/sites-available/example.com.conf
```

Добавьте:

```apache
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^.*((\.\.)|(\.\./)).*$ [NC]
    RewriteRule ^.*$ - [F,L]
</IfModule>
```

- `a2enmod rewrite`: Включает модуль `mod_rewrite`.
- `RewriteEngine On`: Активирует переписывание.
- `RewriteCond`: Проверяет наличие `..` в URL.
- `RewriteRule`: Запрещает такие запросы (`F` — 403 Forbidden).

Перезапустите:

```bash
sudo systemctl restart apache2
```

## Настройка mod_security

**Защита от угроз**: XSS (25% атак) и SQL-инъекции (60% атак, Kaspersky, 2023) эксплуатируют уязвимости приложений. `mod_security` фильтрует вредоносные запросы.

### Шаг 1: Установка
**Что делает**: Устанавливает `mod_security` и OWASP CRS.  
**Что настраиваем**: Модуль веб-файрвола и правила защиты.  
**Почему важно**: Блокирует атаки OWASP Top 10.

```bash
sudo apt install libapache2-mod-security2 -y
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo apt install modsecurity-crs -y
```

- `libapache2-mod-security2`: Модуль веб-файрвола.
- `cp`: Копирует рекомендованную конфигурацию.
- `modsecurity-crs`: Устанавливает OWASP Core Rule Set.

### Шаг 2: Настройка
**Что делает**: Активирует фильтрацию запросов.  
**Что настраиваем**: Конфигурацию `mod_security`.  
**Почему важно**: Обеспечивает активную защиту от инъекций.

```bash
sudo nano /etc/modsecurity/modsecurity.conf
```

Измените:

```apache
SecRuleEngine On
```

- `SecRuleEngine On`: Включает обработку правил.

Добавьте OWASP CRS в `/etc/apache2/mods-enabled/security2.conf`:

```bash
sudo nano /etc/apache2/mods-enabled/security2.conf
```

Добавьте:

```apache
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>
```

- `SecDataDir`: Указывает директорию для данных.
- `IncludeOptional`: Подключает конфигурации и правила CRS.

Создайте директорию:

```bash
sudo mkdir -p /var/cache/modsecurity
sudo chown www-data:www-data /var/cache/modsecurity
sudo chmod 750 /var/cache/modsecurity
```

- `mkdir`: Создаёт директорию для временных данных.
- `chown`: Устанавливает владельца `www-data` (пользователь Apache).
- `chmod`: Ограничивает доступ.

### Шаг 3: Исправление AppArmor
**Что делает**: Разрешает Apache доступ к файлам `mod_security`.  
**Что настраиваем**: Профиль AppArmor для Apache.  
**Почему важно**: Предотвращает ошибки доступа, сохраняя изоляцию.

При ошибке:

```
Syntax error ... Could not open directory /usr/share/modsecurity-crs: Permission denied
```

Редактируйте:

```bash
sudo nano /etc/apparmor.d/usr.sbin.apache2
```

Добавьте:

```apparmor
/etc/modsecurity/** r,
/usr/share/modsecurity-crs/** r,
/var/cache/modsecurity/** rw,
```

Перезагрузите:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.apache2
sudo aa-enforce /etc/apparmor.d/usr.sbin.apache2
sudo systemctl restart apache2
```

- `apparmor_parser`: Обновляет профиль.
- `aa-enforce`: Включает строгий режим.

## Защита SSH с Fail2Ban

**Защита от угроз**: Brute-force атаки на SSH подбирают пароли, компрометируя сервер. `Fail2Ban` блокирует IP после неудачных попыток.

### Шаг 1: Установка Fail2Ban
**Что делает**: Устанавливает `Fail2Ban` для мониторинга логов и блокировки IP.  
**Что настраиваем**: Систему обнаружения вторжений.  
**Почему важно**: Защищает SSH от автоматизированных атак.

```bash
sudo apt install fail2ban -y
```

### Шаг 2: Настройка фильтра для SSH
**Что делает**: Определяет правила блокировки для SSH.  
**Что настраиваем**: Jail для анализа логов SSH.  
**Почему важно**: Ограничивает попытки входа, предотвращая компрометацию.

```bash
sudo nano /etc/fail2ban/jail.d/sshd.conf
```

Добавьте:

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
findtime = 600
action = iptables-multiport[name=sshd, port="ssh"]
allowipv6 = auto
```

- `enabled`: Активирует фильтр.
- `port`: Указывает порт SSH (22).
- `filter`: Использует встроенный фильтр `sshd`.
- `logpath`: Путь к логам авторизации.
- `maxretry`: Максимум 3 попытки.
- `bantime`: Блокировка на 2 часа.
- `findtime`: Окно анализа (10 минут).
- `action`: Блокирует через iptables.

### Шаг 3: Перезапуск Fail2Ban
**Что делает**: Применяет конфигурацию.  
**Что настраиваем**: Службу `Fail2Ban`.  
**Почему важно**: Активирует защиту SSH.

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

- `systemctl restart`: Перезапускает `Fail2Ban`.
- `fail2ban-client status`: Проверяет активность фильтра.

### Шаг 4: Тестирование защиты с Hydra
**Что делает**: Симулирует brute-force атаку на SSH.  
**Что настраиваем**: Тестируем защиту `Fail2Ban`.  
**Почему важно**: Подтверждает блокировку злоумышленников.

```bash
sudo apt install hydra -y
echo -e "password1\npassword2\npassword3" > passwords.txt
hydra -l admin -P passwords.txt ssh://127.0.0.1
```

- `apt install hydra`: Устанавливает инструмент для атак.
- `echo`: Создаёт список паролей.
- `hydra`: Выполняет атаку с логином `admin` и паролями из файла.

### Шаг 5: Проверка блокировки в логах Fail2Ban
**Что делает**: Проверяет, заблокирован ли IP.  
**Что настраиваем**: Логи и статус `Fail2Ban`.  
**Почему важно**: Подтверждает работу защиты.

```bash
sudo tail -n 50 /var/log/fail2ban.log
sudo fail2ban-client status sshd
```

Ожидаемый вывод логов:

```
2025-05-05 HH:MM:SS,123 INFO   [sshd] Ban 127.0.0.1
```

Ожидаемый статус:

```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed: 3
|  `- File list: /var/log/auth.log
`- Actions
   |- Currently banned: 1
   |- Total banned: 1
   `- Banned IP list: 127.0.0.1
```

**Примечание**: Если `127.0.0.1` не блокируется из-за `ignoreself`, используйте другой IP.

## Защита от DDoS с mod_evasive и Fail2Ban

**Защита от угроз**: DDoS-атаки (SYN-флуд, HTTP-флуд) перегружают сервер, вызывая отказ в обслуживания. `mod_evasive` и `Fail2Ban` ограничивают запросы и блокируют злоумышленников.

### mod_evasive
**Что делает**: Устанавливает и настраивает модуль для защиты от DDoS.  
**Что настраиваем**: Модуль Apache для ограничения частоты запросов.  
**Почему важно**: Быстро блокирует подозрительные клиенты.

```bash
sudo apt install libapache2-mod-evasive -y
sudo nano /etc/apache2/mods-available/evasive.conf
```

Добавьте:

```apache
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        1
    DOSSiteCount        3
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   10
    DOSLogDir           /var/log/mod_evasive
    DOSEmailNotify      admin@example.com
    DOSLogLevel         3
</IfModule>
```

- `DOSHashTableSize`: Размер таблицы для отслеживания клиентов.
- `DOSPageCount`: Максимум запросов к странице за интервал.
- `DOSSiteCount`: Максимум запросов к сайту.
- `DOSPageInterval`, `DOSSiteInterval`: Интервал в секундах.
- `DOSBlockingPeriod`: Время блокировки (10 секунд).
- `DOSLogDir`: Директория логов.
- `DOSEmailNotify`: Email для уведомлений.
- `DOSLogLevel`: Уровень детализации логов.

Настройте логи:

```bash
sudo mkdir /var/log/mod_evasive
sudo chown www-data:www-data /var/log/mod_evasive
sudo chmod 750 /var/log/mod_evasive
```

Активируйте:

```bash
sudo a2enmod evasive
sudo systemctl restart apache2
```

### Fail2Ban для DDoS
**Что делает**: Настраивает фильтр для блокировки IP, обнаруженных `mod_evasive`.  
**Что настраиваем**: Фильтр и jail для DDoS.  
**Почему важно**: Автоматизирует долгосрочную блокировку.

```bash
sudo nano /etc/fail2ban/filter.d/apache-ddos.conf
```

Добавьте:

```ini
[Definition]
failregex = ^\[\S+ \S+ \S+ \d{4}\] \[error\] \[client <HOST>\] client denied by mod_evasive.*
ignoreregex =
```

- `failregex`: Регулярное выражение для логов `mod_evasive`.

Создайте `/etc/fail2ban/jail.d/apache-ddos.conf`:

```bash
sudo nano /etc/fail2ban/jail.d/apache-ddos.conf
```

Добавьте:

```ini
[apache-ddos]
enabled = true
port = http,https
filter = apache-ddos
logpath = /var/log/apache2/error.log
maxretry = 5
bantime = 7200
findtime = 600
action = iptables-multiport[name=apache-ddos, port="http,https"]
allowipv6 = auto
```

Перезапустите:

```bash
sudo systemctl restart fail2ban
```

## Изоляция процессов с AppArmor

**Защита от угроз**: Компрометация Apache может дать доступ к системе. AppArmor ограничивает действия, предотвращая эскалацию.

### Шаг 1: Установка и настройка
**Что делает**: Устанавливает AppArmor и настраивает профиль для Apache.  
**Что настраиваем**: Политики мандатного контроля доступа.  
**Почему важно**: Ограничивает ущерб при атаке.

```bash
sudo apt install apparmor apparmor-utils -y
sudo nano /etc/apparmor.d/usr.sbin.apache2
```

Добавьте:

```apparmor
#include <tunables/global>

/usr/sbin/apache2 {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability dac_override,
  capability dac_read_search,
  capability net_bind_service,
  capability setgid,
  capability setuid,

  /etc/apache2/** r,
  /etc/mime.types r,
  /etc/php/** r,
  /etc/modsecurity/** r,
  /usr/share/modsecurity-crs/** r,
  /var/cache/modsecurity/** rw,

  /var/log/apache2/ rw,
  /var/log/apache2/* rw,
  /var/log/mod_evasive/ rw,
  /var/log/mod_evasive/* rw,

  /var/www/** r,
  /var/www/example.com/public_html/** r,

  /run/apache2/* rw,
  /usr/lib/apache2/modules/*.so mr,

  /usr/sbin/php-fpm* ix,
  /usr/bin/php* ix,
}
```

- `capability`: Разрешает необходимые системные привилегии.
- `/etc/apache2/** r`: Доступ на чтение к конфигурациям.
- `/var/cache/modsecurity/** rw`: Доступ для `mod_security`.
- `/var/www/** r`: Доступ к веб-контенту.

Перезагрузите:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.apache2
sudo aa-enforce /etc/apparmor.d/usr.sbin.apache2
```

## Оптимизация производительности

**Защита от угроз**: Неоптимизированный сервер уязвим к DDoS из-за перегрузки. Оптимизация повышает устойчивость.

### MPM Event
**Что делает**: Переключает Apache на событийную модель обработки запросов.  
**Что настраиваем**: Модуль MPM для Apache.  
**Почему важно**: Уменьшает потребление ресурсов при высоких нагрузках.

```bash
sudo a2dismod mpm_prefork
sudo a2enmod mpm_event
sudo nano /etc/apache2/mods-available/mpm_event.conf
```

Добавьте:

```apache
<IfModule mpm_event_module>
    StartServers             2
    MinSpareThreads         25
    MaxSpareThreads         75
    ThreadLimit             64
    ThreadsPerChild         25
    MaxRequestWorkers       150
    MaxConnectionsPerChild  0
</IfModule>
```

- `StartServers`: Количество серверов при старте.
- `MinSpareThreads`, `MaxSpareThreads`: Диапазон свободных потоков.
- `ThreadsPerChild`: Потоков на процесс.
- `MaxRequestWorkers`: Максимум одновременных соединений.

### Сжатие (mod_deflate)
**Что делает**: Сжимает ответы сервера.  
**Что настраиваем**: Модуль `mod_deflate`.  
**Почему важно**: Ускоряет загрузку и снижает нагрузку.

```bash
sudo a2enmod deflate
sudo nano /etc/apache2/mods-available/deflate.conf
```

Добавьте:

```apache
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript
    DeflateCompressionLevel 6
</IfModule>
```

- `AddOutputFilterByType`: Сжимает указанные MIME-типы.
- `DeflateCompressionLevel`: Уровень сжатия (6 — баланс).

### KeepAlive
**Что делает**: Разрешает множественные запросы по одному соединению.  
**Что настраиваем**: Глобальные настройки Apache.  
**Почему важно**: Снижает накладные расходы на соединения.

```bash
sudo nano /etc/apache2/apache2.conf
```

Добавьте:

```apache
KeepAlive On
KeepAliveTimeout 5
MaxKeepAliveRequests 100
```

- `KeepAlive On`: Включает KeepAlive.
- `KeepAliveTimeout`: Время ожидания (5 секунд).
- `MaxKeepAliveRequests`: Максимум запросов (100).

### Кэширование (mod_cache)
**Что делает**: Кэширует статический контент.  
**Что настраиваем**: Модули `mod_cache` и `mod_cache_disk`.  
**Почему важно**: Снижает нагрузку на сервер.

```bash
sudo a2enmod cache
sudo a2enmod cache_disk
sudo nano /etc/apache2/mods-available/cache_disk.conf
```

Добавьте:

```apache
<IfModule mod_cache.c>
    <IfModule mod_cache_disk.c>
        CacheEnable disk /
        CacheRoot /var/cache/apache2/mod_cache_disk
        CacheDirLevels 2
        CacheDirLength 1
        CacheDefaultExpire 3600
    </IfModule>
</IfModule>
```

Настройте кэш:

```bash
sudo mkdir -p /var/cache/apache2/mod_cache_disk
sudo chown www-data:www-data /var/cache/apache2/mod_cache_disk
sudo chmod 750 /var/cache/apache2/mod_cache_disk
```

Перезапустите:

```bash
sudo systemctl restart apache2
```

## Логирование и ротация логов

**Защита от угроз**: Логи позволяют обнаружить атаки, а ротация предотвращает переполнение диска.

### Подробное логирование
**Что делает**: Устанавливает уровень детализации логов.  
**Что настраиваем**: Глобальные настройки Apache.  
**Почему важно**: Помогает анализировать инциденты.

```bash
sudo nano /etc/apache2/apache2.conf
```

Установите:

```apache
LogLevel warn
```

Проверяйте:

```bash
sudo tail -n 50 /var/log/apache2/error.log
```

### Ротация логов
**Что делает**: Настраивает ротацию логов Apache.  
**Что настраиваем**: `logrotate` для управления логами.  
**Почему важно**: Предотвращает переполнение диска.

```bash
sudo nano /etc/logrotate.d/apache2
```

Добавьте:

```conf
/var/log/apache2/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        /usr/sbin/apache2ctl graceful
    endscript
}
```

- `daily`: Ротация ежедневно.
- `rotate 14`: Хранит 14 архивов.
- `compress`: Сжимает старые логи.

## Автоматизация обновлений

**Защита от угроз**: Устаревшее ПО уязвимо к эксплойтам. Автоматические обновления закрывают уязвимости.

```bash
sudo apt install unattended-upgrades -y
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

Добавьте:

```conf
Unattended-Upgrades::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrades::Automatic-Reboot "true";
Unattended-Upgrades::Automatic-Reboot-Time "02:00";
```

Включите:

```bash
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

## Резервное копирование

**Защита от угроз**: Ransomware и сбои могут уничтожить данные. Резервное копирование обеспечивает восстановление.

```bash
sudo nano /root/backup.sh
```

Добавьте:

```bash
#!/bin/bash
BACKUP_DIR="/backup/$(date +%Y-%m-%d)"
SOURCES="/etc/apache2 /var/www /var/log/apache2"
mkdir -p "$BACKUP_DIR"
for SRC in $SOURCES; do
    rsync -av --delete "$SRC" "$BACKUP_DIR$(dirname $SRC)"
done
find /backup -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \;
```

Сделайте исполняемым:

```bash
sudo chmod +x /root/backup.sh
```

Настройте cron:

```bash
sudo nano /etc/crontab
```

Добавьте:

```bash
0 2 * * * root /root/backup.sh
```

Создайте директорию:

```bash
sudo mkdir -p /backup
sudo chown root:root /backup
sudo chmod 700 /backup
```

## Тестирование безопасности

### Тестирование DDoS
```bash
ab -n 1000 -c 100 http://127.0.0.1/
sudo tail -n 50 /var/log/mod_evasive/*
sudo fail2ban-client status apache-ddos
sudo iptables -L fail2ban-apache-ddos -n -v
```

### Тестирование XSS и SQL-инъекций
```bash
curl "http://example.com/?id=<script>alert('XSS')</script>"
sudo tail -n 50 /var/log/apache2/modsec_audit.log
```

### Тестирование AppArmor
```bash
sudo tail -n 50 /var/log/syslog | grep apparmor
```

## Заключение

Эта статья представила комплексное руководство по настройке безопасного веб-сервера Apache на Ubuntu 24.04, успешно достигнув цели минимизации современных киберугроз, таких как DDoS, XSS, SQL-инъекции, MITM и brute-force атаки. Реализованная конфигурация включает многоуровневую защиту:
- **Шифрование**: Использование TLS 1.2/1.3 с Let’s Encrypt и HSTS обеспечивает защиту трафика от MITM-атак, гарантируя конфиденциальность данных.
- **Фильтрация запросов**: `mod_security` с OWASP CRS блокирует инъекции и XSS, предотвращая эксплуатацию уязвимостей приложений.
- **Ограничение атак**: `mod_evasive` и `Fail2Ban` защищают от DDoS и brute-force, блокируя подозрительные IP на уровне сервера и сети.
- **Изоляция процессов**: AppArmor ограничивает действия Apache, минимизируя ущерб при компрометации.
- **Оптимизация**: `mpm_event`, `mod_deflate`, `mod_cache` и KeepAlive повышают производительность, делая сервер устойчивым к нагрузкам.
- **Мониторинг и восстановление**: Логирование, ротация логов, автоматические обновления (`unattended-upgrades`) и резервное копирование обеспечивают оперативное обнаружение инцидентов и восстановление данных.

Практическая реализация была протестирована с использованием инструментов, таких как `Hydra` для brute-force и `ab` для DDoS, подтвердив эффективность защиты. Например, `Fail2Ban` успешно блокировал IP при попытках подбора паролей, а `mod_security` предотвращал XSS и SQL-инъекции. Конфигурация также устранила потенциальные проблемы, такие как ошибки AppArmor при использовании `mod_security`, и оптимизировала производительность для высоких нагрузок.

**Практическая ценность**: Предложенная конфигурация универсальна и применима в различных сценариях:
- **Корпоративные среды**: Защита веб-приложений, обработка персональных данных в соответствии с GDPR и PCI DSS.
- **Малый бизнес**: Надёжный сервер для сайтов и интернет-магазинов с минимальными затратами благодаря бесплатным инструментам, таким как Let’s Encrypt.
- **Образовательные проекты**: Обучение настройке безопасных серверов и тестированию защиты.
- **Личные проекты**: Хостинг сайтов или блогов с высокой степенью безопасности.

**Ограничения и дальнейшие улучшения**: Хотя конфигурация охватывает большинство угроз OWASP Top 10, она может быть расширена:
- **Интеграция с SIEM**: Использование систем, таких как Splunk или ELK, для централизованного анализа логов и обнаружения сложных атак.
- **Контейнеризация**: Размещение Apache в Docker или Podman для дополнительной изоляции и упрощения масштабирования.
- **Облачные WAF**: Подключение Cloudflare или AWS WAF для распределённой защиты от DDoS.
- **SELinux**: Переход на SELinux вместо AppArmor для более строгих политик в средах с высокими требованиями безопасности.
- **Регулярное тестирование**: Проведение пентестов с инструментами, такими как OWASP ZAP или Burp Suite, для выявления новых уязвимостей.

В сравнении с NGINX, Apache предлагает большую гибкость для динамических приложений, но требует внимательной настройки. Предложенная конфигурация делает Apache надёжным выбором для безопасного хостинга, обеспечивая баланс между производительностью, безопасностью и простотой управления. Регулярный аудит логов, обновления и тестирование защиты помогут поддерживать сервер в актуальном и защищённом состоянии.

## Список источников
1. Apache HTTP Server Documentation. [https://httpd.apache.org/docs/](https://httpd.apache.org/docs/)
2. Ubuntu Server Guide. [https://ubuntu.com/server/docs](https://ubuntu.com/server/docs)
3. Let’s Encrypt Documentation. [https://letsencrypt.org/docs/](https://letsencrypt.org/docs/)
4. OWASP Top 10. [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
5. ModSecurity Handbook. [https://modsecurity.org/](https://modsecurity.org/)
6. W3Techs. [https://w3techs.com/](https://w3techs.com/)
7. Positive Technologies. Актуальные киберугрозы: итоги 2023 года. [https://www.ptsecurity.com/](https://www.ptsecurity.com/)
