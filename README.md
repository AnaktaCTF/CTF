# Статьи от нашей команды

В этом репозитории собраны статьи и полезные материалы для тех, кто интересуется CTF.

## Наши статьи по разделам

### 🔰 [Курс молодого бойца](/Misc/young_fighter_course.md)
Вводный курс для начинающих в сфере информационной безопасности. Здесь вы найдете основные понятия и первые шаги в мире кибербезопасности. Если уже готовы, то переходите к другим нашим статьям в интересных для вас разделах!

### Криптография
* [Атаки на криптосистемы, основанные на эллиптических кривых (ECC)](Cryptography/ECC.md)
* [Практическая реализация Padding Oracle Attack в CBC-режиме на Python](/Cryptography/Padding_Oracle_Attack.md)

### Реверс-инжиниринг
* [Автоматизация статического анализа бинарных файлов с помощью Radare2 и r2pipe на Python](Reverse/python_static_analysis.md)
* [Обход лицензирования и патчинг в CTF](Reverse/program_patching.md)
* [Автоматизация реверс-инжиниринга с помощью Angr](/Reverse/AutomatingReverseEngineeringwithAngr.md)
* [Динамическая инструментализация приложений с помощью Frida и Python](/Reverse/Frida_Python_Instrumentation.md)
  
### WEB
* 🌐 [Введение в Web.](/WEB/introduction_to_the_Web.md)  
Базовые знания о веб-технологиях, необходимые для понимания безопасности веб-приложений.
* [Уязвимость OS-command Injection](/WEB/OS_Injection.md)
* [Web fingerprinting](/WEB/web-fingerprinting.md)
* [XSS уязвимости](/WEB/XSS.md)
* [Работа с API в CTF: безопасность и уязвимости](/WEB/working%20with%20API.md)
* [Уязвимость XXE при парсинге XML](/WEB/XXE_Guide.md)
* [SQL-инъекция](/WEB/SQL%20Injection.md)
* [JWT безопасность и взлом](/WEB/JWT_testing.md)
* [Безопасность и эксплуатация GraphQL](WEB/GraphQL.md)
* [Безопасность и уязвимости Смарт-Контрактов](/WEB/Smart-contracts_OWASP_TOP10.md)
* [Атаки реентерабельности в смарт-контрактах SC05:2025 - Reentrancy](/WEB/Reentrancy_Smart-Contract_Vulnerability.md)
* [Цифровые сертификаты в SSL/TLS](/WEB/Digital%certificates%in%SSL_TLS.md)
* [Отказ в обслуживании (Denial of Service SC10:2025, DoS) в смарт-контрактах](/WEB/DOS_Attack_Smart-Contracts.md)
* [Уязвимости контроля доступа в смарт-контрактах (SC01:2025)](/WEB/Access_Control_Vulnerabilities_in_Smart_Contracts.md)
* [Настройка и безопасная конфигурация сервера APACHE](/WEB/secure_apache_configuration.md)

### Форензика
* [Основные этапы процесса реагирования на инциденты ИБ](/Forensic/Основные%20этапы%20процесса%20реагирования%20на%20инциденты%20ИБ.md)
* [Особенности NTFS для сокрытия данных](/Forensic/NTFS_features_to_hide_data.md)
* [DPI Engine](/Forensic/DPI%Engine.md)
* [Masquerading](/Forensic/Masquerading.md)
* [Анализ дампов памяти Windows (Volatility 3 и Python)](/Forensic/Анализ%20дампов%20памяти%20Windows.md)

### OSINT
*  [Активное сканирование](/OSINT/Active_Scanning.md) 
* 🕵️ [Введение в OSINT](/OSINT/introduction_to_OSINT.md)  
Узнайте об основах Open Source Intelligence (OSINT) - методах сбора и анализа информации из открытых источников.
* [Введение в GeoINT](/OSINT/GeoINT_article.md)  
Здесь вы узнаете про Геопространственную разведку (GeoINT) - виды разведки, как применять с примерами и полезныцми ссылками.
* [Google Dorks. Основы.](/OSINT/introduction-to-googledorks.md)
* [Обзор инструментов для OSINT](/OSINT/osint-instruments.md)

### Стеганография
* [Стеганография в звуковых файлах](/steganography/audio_steganography.md)
* [Стеганография в изображении](/steganography/image_steganography.md)
* [Стеганография в сетевом трафике](/steganography/network-steganography.md)
* [Стеганография в исполняемых файлах](/steganography/executable-steganography.md)
  
### PWN
* [Процесс и поток](/PWN/Процесс%20и%20поток.md)
* [Privilege Escalation](/PWN/privilege_escalation.md)
* [Обход ASLR и DEP в современных эксплойтах](/PWN/Bypassing_ASLR_and_DEP_in_modern_exploits.md)
* [Credential Dumping](/PWN/Credential_Dumping.md)
* [Эксплуатация уязвимостей ядра](/PWN/Kernel_Exploitation.md)
* [Heap Exploitation: Use-After-Free](https://github.com/AnaktaCTF/CTF/blob/main/PWN/UAF.md)
* [Эксплуатация уязвимостей форматной строки](PWN/Format_String_Exploitation.md)

### Misc
* [Организация управляемого доступа в ОС Windows](/Misc/Организация%20управляемого%20доступа%20в%20ОС%20Windows.md)
* [LDAP в Active Directory](/Misc/Pentest_Active_Directory_LDAP.md)
* [Туннелирование Соединений](/Misc/tunneling_of_connections.md)
* [Тестирование почтовых протоколов SMTP, POP3, IMAP](/Misc/Postal_Protocols.md)
* [Авторизация через SSH: как устроен SSH-сервер, ключи аутентификации и PAM-аутентификация](/Misc/SSH.md)
* [WinRM в пентесте](/Misc/WinRM_in_pentest.md)
* [Атака Kerberoasting](/Misc/Kerberoasting.md)
* [Пенетест облачной инфраструктуры](/Misc/Cloud%20CTF.md)
* [Атака AS-REP Roasting](/Misc/AS_REP_Roasting.md)
* [Kerberos](/Misc/Kerberos.md)
* [Протокол SMB](/Misc/SMB_Protocol.md)
* [Введение в fuzzing](Misc/fuzzing.md)
* [Разработка эксплойтов для современных систем Windows](Misc/Exploit-Development-ModernWindowsSystems.md)
* [Протокол RPC](/Misc/RPC_Protocol.md)
* [Основы Active Directory](/Misc/Active_Directory.md)

### WriteUps
* [WriteUp с Capture the Intruder (CTI)](/WriteUps/CTI_writeup.md)  
Решение задач с реального соревнования. Первое задание по реверсу с декомпеляцией и анализом полученного кода. Вторая задача по форензике про анализ логов. 

### RealLife
* [Безопасность Wi-Fi сетей: Перехват хендшейков](/RealLife/Capturing_WiFi_Handshakes.md)
* [Безопасность Wi-Fi сетей: Evil Twin](/RealLife/Evil_Twin_Wifi.md)

## Полезные ресурсы

### 📚 [Awesome-list](/Misc/awesome.md)
Подборка полезных ресурсов, инструментов и материалов по различным аспектам информационной безопасности.

## 👾 Наша команда
Мы CTF команда Московского Политеха. Принимаем участие в различных соревнований, обучаем и помогаем молодым бойцам и участникам CTF.
[CTFtime](https://ctftime.org/team/150251)

