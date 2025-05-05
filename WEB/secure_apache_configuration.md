# Настройка и безопасная конфигурация сервера Apache на Ubuntu

![image](https://github.com/user-attachments/assets/096eb13b-d943-4e15-abd9-3daad45ece5f)


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

![image](https://github.com/user-attachments/assets/3959a7d5-cc64-4201-b0db-57d75b5b5eab)


### Шаг 2: Установка Apache
**Что делает**: Устанавливает Apache и его зависимости.  
**Что настраиваем**: Веб-сервер Apache (`apache2`) для обработки HTTP-запросов.  
**Почему важно**: Свежая версия Apache минимизирует риски эксплуатации уязвимостей.

```bash
sudo apt install apache2 -y
```

- `apt install apache2`: Устанавливает пакет `apache2`.
- `-y`: Автоматически соглашается с установкой.

![image](https://github.com/user-attachments/assets/b8a9fc98-8c57-4cc9-8f7e-3f3fe7a39cbf)


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

![image](https://github.com/user-attachments/assets/306d760f-ece7-4890-9e06-d50230d0d506)


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
![image](https://github.com/user-attachments/assets/3cdf9628-4073-4a2c-8559-0d27b12ab302)

- `allow ssh`: Открывает порт 22 для SSH (удалённое управление).
![image](https://github.com/user-attachments/assets/adcbfa85-d20d-4007-9772-517bf193534d)

- `allow 80/tcp`: Открывает порт 80 для HTTP.
- `allow 443/tcp`: Открывает порт 443 для HTTPS.
![image](https://github.com/user-attachments/assets/7fb4657c-0954-483f-b2cb-d4f788ddd83e)


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
![image](https://github.com/user-attachments/assets/d239a67c-fc9d-4db6-b534-8cb377859109)


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
![image](https://github.com/user-attachments/assets/4dab6b65-4044-4dfe-a5e2-98d6a81eeb83)


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
![image](https://github.com/user-attachments/assets/45c253d2-7ee6-49d1-9727-5ecdb79ef327)


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
![image](https://github.com/user-attachments/assets/499d916e-8349-4530-a3fe-c556758fc327)


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

![image](https://github.com/user-attachments/assets/9faff8bf-1681-4d9a-a84c-96477e0523b3)


Активируйте `mod_headers`:

```bash
sudo a2enmod headers
sudo systemctl restart apache2
```

- `a2enmod headers`: Включает модуль для обработки заголовков.
- `systemctl restart apache2`: Перезапускает Apache для применения изменений.
![image](https://github.com/user-attachments/assets/77be8cf2-be7e-4f3c-b3ce-7d8e29072242)


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
![image](https://github.com/user-attachments/assets/fb1bfcd0-c8a7-4c38-8383-cecee4b1b4f6)

![image](https://github.com/user-attachments/assets/24e02374-9ee3-4feb-a6e3-abb61d805fe6)

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
![image](https://github.com/user-attachments/assets/c026c2d5-13ca-488d-8d72-6f5e86d13d05)

Перезапустите:

```bash
sudo systemctl restart apache2
```
![image](https://github.com/user-attachments/assets/84dbf653-b27e-4158-98ee-2b1f7b135f07)

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
![image](https://github.com/user-attachments/assets/1cd1c76e-1297-46ba-bb6d-89f4d7e7db1b)


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
![image](https://github.com/user-attachments/assets/09e81adb-3fc5-412c-94ec-0a797d77a7d3)

Создайте директорию:

```bash
sudo mkdir -p /var/cache/modsecurity
sudo chown www-data:www-data /var/cache/modsecurity
sudo chmod 750 /var/cache/modsecurity
```

- `mkdir`: Создаёт директорию для временных данных.
- `chown`: Устанавливает владельца `www-data` (пользователь Apache).
- `chmod`: Ограничивает доступ.

Активация:
![image](https://github.com/user-attachments/assets/61cf7af2-7d70-45e1-80eb-6bfbb933ffb6)


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
![image](https://github.com/user-attachments/assets/701df074-481e-40a8-8bad-ea7423fdcf2b)
![image](https://github.com/user-attachments/assets/6cee5ed9-38f1-44bd-8a8a-0bdd382442b7)


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
![image](https://github.com/user-attachments/assets/2074a914-2a1f-45dc-a308-b8665e0a29b2)

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
![image](https://github.com/user-attachments/assets/b46745fa-603c-4f5a-9dea-b728ccaad78e)

### Шаг 4: Тестирование защиты с Hydra
**Что делает**: Симулирует brute-force атаку на SSH.  
**Что настраиваем**: Тестируем защиту `Fail2Ban`.  
**Почему важно**: Подтверждает блокировку злоумышленников.

```bash
sudo apt install hydra -y
echo -e "password1\npassword2\npassword3" > passwords.txt
hydra -l admin -P passwords.txt ssh://127.0.0.1
```
В нашем случае также необходимо разрешить блокировку собственного адреса, так аттака проводиться с него:

```
ignoreself = false
ignoreip = 
```
![image](https://github.com/user-attachments/assets/e88dcb68-96a0-4f6e-a3a8-73eaa91a8bd8)
![image](https://github.com/user-attachments/assets/51041b85-92ac-4d9b-ab2d-6971a0661e8c)
![image](https://github.com/user-attachments/assets/f340f397-4fb1-446a-928f-91512607f5b4)


- `apt install hydra`: Устанавливает инструмент для атак.
![image](https://github.com/user-attachments/assets/ca7043b5-3e5a-470a-9e7b-687678c23ceb)
- `echo`: Создаёт список паролей.
- `hydra`: Выполняет атаку с логином `admin` и паролями из файла.
![image](https://github.com/user-attachments/assets/32c019ce-6b52-4448-95c0-0d1f2718125b)

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
![image](https://github.com/user-attachments/assets/5a0d90c1-84af-4b23-97dc-5a144824b2ee)

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
![image](https://github.com/user-attachments/assets/c8bb6970-41e6-44df-88e2-701f3c7ed45d)

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
![image](https://github.com/user-attachments/assets/0d728fdc-4892-486b-9dea-48f10f79fc38)


Настройте логи:

```bash
sudo mkdir /var/log/mod_evasive
sudo chown www-data:www-data /var/log/mod_evasive
sudo chmod 750 /var/log/mod_evasive
```
![image](https://github.com/user-attachments/assets/70d9cd8a-f3df-44bf-bdaa-d7649aaf5f65)

Активируйте:

```bash
sudo a2enmod evasive
sudo systemctl restart apache2
```
![image](https://github.com/user-attachments/assets/4ac32f06-53f1-4861-be60-03706f7d7620)

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
![image](https://github.com/user-attachments/assets/fc610bd8-33b6-462c-8729-3430d172b672)

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
![image](https://github.com/user-attachments/assets/8ddb002e-d69e-43d0-8cc2-e80c9ec888d2)

Перезапустите:

```bash
sudo systemctl restart fail2ban
```

Проверка правил iptables:
```
sudo iptables -L -n -v
```
![image](https://github.com/user-attachments/assets/9e26c863-d62b-4187-aaa1-fe5d4e815ac9)
![image](https://github.com/user-attachments/assets/1a6afac8-8047-42f8-b3ca-1a71c0ff18ef)

Тестирование DDoS-атаки (например, с помощью ab):
```
ab -n 1000 -c 100 http://127.0.0.1/
```
![image](https://github.com/user-attachments/assets/346fc1c5-2c2b-4db7-98f8-44f2ef1b1909)


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
![image](https://github.com/user-attachments/assets/0a7a4532-f500-49fb-9e77-9ca9077a19d3)

Перезагрузите:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.apache2
sudo aa-enforce /etc/apparmor.d/usr.sbin.apache2
```
![image](https://github.com/user-attachments/assets/2461292e-f190-4dcc-9795-c77829b0087f)

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
![image](https://github.com/user-attachments/assets/503c1d6d-b6d9-4745-9b5b-7ceb7c08c517)

![image](https://github.com/user-attachments/assets/7ca2670b-7cf7-419e-abaa-04632b6767aa)

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
![image](https://github.com/user-attachments/assets/f140861a-9ed2-42f6-9645-a8a1902f45ae)

Активация:
```
sudo a2enmod deflate
```
![image](https://github.com/user-attachments/assets/b7c1dc08-1d90-4071-8c41-266410490fe4)


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
![image](https://github.com/user-attachments/assets/7084de64-64e5-487f-a89f-ecf81094331a)

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
![image](https://github.com/user-attachments/assets/99278a42-199d-4c25-8609-c7197eb88dee)

Активация:
```
sudo a2enmod cache cache_disk
sudo systemctl restart apache2
```
![image](https://github.com/user-attachments/assets/a5215201-50f2-4233-ba32-ec246d128bfd)

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
![image](https://github.com/user-attachments/assets/64c8a09c-c96f-4fe8-a3ab-5fa1cb2ed0b8)

Проверяйте:

```bash
sudo tail -n 50 /var/log/apache2/error.log
```
![image](https://github.com/user-attachments/assets/e4296860-7dc2-4b02-8743-724fdcc7af87)

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
![image](https://github.com/user-attachments/assets/a3bfe60e-4745-4db7-b9f8-ecc3a32bc8e4)


## Автоматизация обновлений

**Защита от угроз**: Устаревшее ПО уязвимо к эксплойтам. Автоматические обновления закрывают уязвимости.

```bash
sudo apt install unattended-upgrades -y
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```
![image](https://github.com/user-attachments/assets/ca4e8a9a-20a6-47b4-89b1-797bf3d7d96d)

Добавьте:

```conf
Unattended-Upgrades::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrades::Automatic-Reboot "true";
Unattended-Upgrades::Automatic-Reboot-Time "02:00";
```
![image](https://github.com/user-attachments/assets/6be7e5e0-32cf-4869-b187-d750484a412c)

Включите:

```bash
sudo dpkg-reconfigure --priority=low unattended-upgrades
```
![image](https://github.com/user-attachments/assets/fb978f6b-609a-44bc-abd9-43b2759c2116)


## Резервное копирование

**Защита от угроз**: Ransomware и сбои могут уничтожить данные. Резервное копирование обеспечивает восстановление.

```bash
sudo nano /root/backup.sh
```
![image](https://github.com/user-attachments/assets/06cc7462-8d74-4e49-9178-2af064246df3)

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
![image](https://github.com/user-attachments/assets/b1d9bc9b-f15f-428d-9249-d13fee4a91eb)

Добавьте:

```bash
0 2 * * * root /root/backup.sh
```
![image](https://github.com/user-attachments/assets/375747ee-7f15-4dc9-8e3b-14c96ee9ca43)

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
1.	Apache HTTP Server Documentation. URL: https://httpd.apache.org/docs/
2.	Ubuntu Server Guide. URL: https://ubuntu.com/server/docs
3.	Let’s Encrypt Documentation. URL: https://letsencrypt.org/docs/
4.	OWASP Top 10. URL: https://owasp.org/www-project-top-ten/
5.	Сергей Волох. Ubuntu Linux с нуля. — СПб.: БХВ-Петербург, 2021. — 417 с.
6.	ModSecurity Handbook. URL: https://modsecurity.org/
7.	W3Techs - World Wide Web Technology Surveys. URL: https://w3techs.com/
8.	Positive Technologies. Актуальные киберугрозы: итоги 2023 года. URL: https://www.ptsecurity.com/ru-ru/research/analytics/
9.	Куклин Д. Безопасность Apache: краткое руководство. URL: https://habr.com/ru/articles/145215/
10.	13 советов по усилению безопасности веб-сервера Apache. URL: https://blog.sedicomm.com/2020/03/17/13-sovetov-po-usileniyu-bezopasnosti-
11.	Как установить и настроить веб-сервер Apache. URL: https://selectel.ru/blog/tutorials/how-to-install-and-configure-apache-web-server/
12.	Защита веб-серверов от XSS и SQL-инъекций. URL: https://support.kaspersky.com/help/Corporate_App_Catalog/TR1/ru-RU/248893.htm
13.	Оптимизация Apache для высокой производительности. URL: https://habr.com/ru/articles/148489/
14.	Анализ логов Apache для обеспечения безопасности. URL: https://habr.com/ru/sandbox/21382/
15.	Безопасность веб-серверов с mod_rewrite. URL: https://habr.com/ru/articles/509122/
16.	Лучшие практики SSL/TLS для веб-серверов. URL: https://habr.com/ru/companies/globalsign/articles/414405/
