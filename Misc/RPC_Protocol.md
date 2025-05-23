- [1. Введение в RPC](#1-введение-в-rpc)
  - [Что такое удалённый вызов процедур](#что-такое-удалённый-вызов-процедур)
  - [Зачем нужен RPC](#зачем-нужен-rpc)
  - [История и развитие](#история-и-развитие)
- [2. Принцип работы протокола RPC](#2-принцип-работы-протокола-rpc)
  - [Клиент-серверная архитектура](#клиент-серверная-архитектура)
  - [Stub и Skeleton](#stub-и-skeleton)
  - [Сериализация и передача данных](#сериализация-и-передача-данных)
  - [Ответ и завершение вызова](#ответ-и-завершение-вызова)
- [3. Преимущества и недостатки RPC](#3-преимущества-и-недостатки-rpc)
  - [Преимущества RPC](#преимущества-rpc)
  - [Недостатки RPC](#недостатки-rpc)
  - [Баланс между удобством и контролем](#баланс-между-удобством-и-контролем)
- [4. Популярные реализации и применения RPC](#4-популярные-реализации-и-применения-rpc)
  - [Популярные реализации RPC](#популярные-реализации-rpc)
    - [1. gRPC (Google Remote Procedure Call)](#1-grpc-google-remote-procedure-call)
    - [2. JSON-RPC](#2-json-rpc)
    - [3. XML-RPC](#3-xml-rpc)
    - [4. Apache Thrift](#4-apache-thrift)
  - [Применение RPC в реальных проектах](#применение-rpc-в-реальных-проектах)
    - [1. Микросервисы](#1-микросервисы)
    - [2. Взаимодействие клиент-сервер](#2-взаимодействие-клиент-сервер)
    - [3. Облачные и распределённые системы](#3-облачные-и-распределённые-системы)
    - [4. IoT и встраиваемые системы](#4-iot-и-встраиваемые-системы)
- [5. RPC в Active Directory](#5-rpc-в-active-directory)
  - [1. Почему Active Directory использует RPC](#1-почему-active-directory-использует-rpc)
  - [2. Используемые порты и протоколы](#2-используемые-порты-и-протоколы)
  - [3. Примеры сервисов AD, использующих RPC](#3-примеры-сервисов-ad-использующих-rpc)
  - [4. Проблемы и диагностика RPC в AD](#4-проблемы-и-диагностика-rpc-в-ad)
  - [5. Безопасность и защита RPC в AD](#5-безопасность-и-защита-rpc-в-ad)
- [Заключение](#заключение)

# 1. Введение в RPC

![1](https://github.com/ShAmRoWw/articles/blob/main/article_rpc/1.png)

**RPC (Remote Procedure Call)** — это технология, позволяющая одной программе (обычно клиенту) вызывать функции или процедуры, находящиеся на другом компьютере (обычно сервере), так же просто, как если бы они выполнялись локально. Основная цель RPC — скрыть детали сетевого взаимодействия, упростив разработку распределённых приложений.

## Что такое удалённый вызов процедур

Удалённый вызов процедур — это механизм, при котором приложение может выполнить код, находящийся на другом устройстве, как если бы этот код был частью самого приложения. Это концептуально похоже на обычный вызов функции в языке программирования, с тем отличием, что выполнение происходит в удалённой среде.

## Зачем нужен RPC

В современном мире распределённых систем и микросервисной архитектуры программы часто состоят из множества компонентов, которые взаимодействуют друг с другом через сеть. RPC позволяет:

- организовать чёткое взаимодействие между этими компонентами;
    
- сократить количество шаблонного кода, связанного с передачей данных по сети;
    
- повысить читаемость и удобство поддержки кода;
    
- реализовать взаимодействие между различными языками программирования и платформами.
    

## История и развитие

RPC как концепция появилась ещё в 1970-х годах и с тех пор эволюционировала. Первоначально реализованный в виде простых протоколов (например, Sun RPC), он со временем обогатился новыми форматами передачи данных (XML, JSON, Protocol Buffers) и более надёжными транспортами (HTTP/2, TCP). Современные реализации, такие как **gRPC**, обеспечивают высокую производительность, поддержку потоков и двусторонней связи.

# 2. Принцип работы протокола RPC

Удалённый вызов процедур (RPC) маскирует сложность сетевого взаимодействия, позволяя вызывать удалённые функции так же, как и локальные. Однако за этой простотой стоит хорошо организованный механизм, обеспечивающий связь между клиентом и сервером. Разберём пошагово, как всё работает.

![2](https://github.com/ShAmRoWw/articles/blob/main/article_rpc/2.png)

## Клиент-серверная архитектура

RPC функционирует по модели **"клиент-сервер"**:

- **Клиент** — сторона, инициирующая вызов удалённой функции.
    
- **Сервер** — сторона, на которой находится реализованная функция и которая отвечает на запрос.
    

Клиент вызывает не реальную функцию, а её _локального представителя_ (stub), который скрывает детали отправки данных через сеть. Сервер в свою очередь использует _обработчик запроса_ (skeleton), чтобы принять вызов, распознать его и вызвать нужную функцию с переданными аргументами.

## Stub и Skeleton

Ключевую роль в RPC играют две вспомогательные компоненты:

- **Stub (заглушка)** — клиентская часть, которая имитирует локальный вызов функции. При вызове:
    
    - она сериализует (кодирует) аргументы;
        
    - отправляет их по сети на сервер;
        
    - получает ответ и десериализует его;
        
    - возвращает результат вызывающему коду.
        
- **Skeleton** — серверная часть, которая:
    
    - принимает запрос;
        
    - десериализует аргументы;
        
    - вызывает соответствующую процедуру;
        
    - сериализует результат;
        
    - отправляет его обратно клиенту.
        

Этот подход позволяет разработчику не заботиться о сетевых деталях: всё происходит "прозрачно".

## Сериализация и передача данных

Перед вызовом удалённой функции, её аргументы необходимо **сериализовать** — преобразовать в формат, пригодный для передачи по сети. Часто используются форматы:

- **JSON** (в JSON-RPC) — удобен и читаем, но менее эффективен по объёму;
    
- **XML** (в XML-RPC) — старее и тяжелее, но всё ещё применяется;
    
- **Protocol Buffers (protobuf)** — бинарный компактный формат, используемый в gRPC.
    

После сериализации данные передаются по сети с использованием протоколов вроде **HTTP**, **TCP**, или более современных, например **HTTP/2** (в gRPC).

## Ответ и завершение вызова

После выполнения функции на сервере, результат проходит обратный путь:

1. Сериализуется;
    
2. Отправляется клиенту;
    
3. Десериализуется stub'ом;
    
4. Возвращается вызывающему коду.
    

Таким образом, вызывающая сторона получает результат как будто от локального вызова.

# 3. Преимущества и недостатки RPC

![3](https://github.com/ShAmRoWw/articles/blob/main/article_rpc/3.png)

Протокол удалённого вызова процедур (RPC) широко используется в распределённых системах, но, как и любая технология, он имеет как сильные стороны, так и определённые ограничения. Ниже рассмотрены основные **преимущества** и **недостатки** RPC-подхода.

## Преимущества RPC

**1. Простота использования и абстракция сетевой логики**  
RPC позволяет разработчику вызывать удалённые функции так же, как локальные. Все детали сетевого взаимодействия — сериализация, передача данных, получение ответа — скрыты в stub/skeleton-слоях. Это значительно упрощает разработку и ускоряет реализацию распределённых приложений.

**2. Унификация и стандартизация взаимодействия**  
Многие реализации RPC используют стандартные форматы обмена данными (например, JSON, Protobuf), что позволяет легко интегрировать компоненты, написанные на разных языках и работающие на разных платформах.

**3. Повторное использование существующего кода**  
При переходе от монолитной архитектуры к распределённой с помощью RPC можно минимально модифицировать существующий код, просто "обернув" функции в сетевые вызовы.

**4. Интеграция с инструментами и фреймворками**  
Современные системы (например, gRPC) имеют встроенные механизмы генерации кода, автодокументации, поддержки потоковых соединений и аутентификации, что делает внедрение безопасным и масштабируемым.

## Недостатки RPC

**1. Зависимость от сети и повышенная чувствительность к сбоям**  
RPC-приложения уязвимы к задержкам, обрывам соединения и другим сетевым проблемам. Поскольку вызов функции "выглядит" как локальный, разработчики могут недооценить риски, связанные с сетевыми сбоями и временем отклика.

**2. Сложности отладки и мониторинга**  
Из-за абстракции сетевого взаимодействия бывает сложно быстро отследить, где именно возникла ошибка — в клиенте, на сервере, при передаче данных, или в процессе сериализации/десериализации.

**3. Ограниченная переносимость между разными RPC-системами**  
Хотя существуют стандартные реализации, переход между различными протоколами (например, с JSON-RPC на gRPC) может требовать значительной переработки кода.

**4. Недостаточная гибкость при сложных сценариях**  
В отличие от REST, где ресурсы описываются через URI и могут быть закэшированы или обработаны прокси, RPC больше ориентирован на процедурный подход. Это может затруднить реализацию некоторых HTTP-функций (например, кэширования, idempotency, повторов запросов).

## Баланс между удобством и контролем

RPC — это мощный инструмент, который работает отлично в строго определённых сценариях: когда требуется тесное взаимодействие между сервисами, высокая производительность и чёткая типизация. Однако при разработке распределённых систем важно учитывать возможные **тонкие места** и дополнять RPC другими механизмами: ретраями, тайм-аутами, логированием и трассировкой.

# 4. Популярные реализации и применения RPC

На протяжении десятилетий протокол RPC получил множество реализаций, каждая из которых ориентирована на определённые задачи, платформы и форматы данных. Современные разработки расширяют классический подход, добавляя безопасность, производительность и поддержку различных языков программирования.

## Популярные реализации RPC

### 1. gRPC (Google Remote Procedure Call)

![4](https://github.com/ShAmRoWw/articles/blob/main/article_rpc/4.png)

- Разработан Google и основан на Protocol Buffers (protobuf) — бинарном, компактном и эффективном формате сериализации.
    
- Использует HTTP/2, что обеспечивает:
    
    - многопоточность (streaming),
        
    - двустороннюю передачу данных (bidirectional streaming),
        
    - сжатие заголовков и быструю передачу.
        
- Имеет официальную поддержку более чем для 10 языков: Go, Java, Python, C++, C#, Node.js и др.
    
- Широко применяется в микросервисных архитектурах, особенно в Kubernetes-средах.
    
- Примеры использования: Netflix, Square, Google Cloud.
    

### 2. JSON-RPC

![5](https://github.com/ShAmRoWw/articles/blob/main/article_rpc/5.png)

- Лёгковесная и человекочитаемая реализация, использующая JSON для сериализации.
    
- Прост в реализации, но менее производителен по сравнению с gRPC.
    
- Работает по различным транспортам: HTTP, WebSocket и т. д.
    
- Хорошо подходит для приложений с низкой нагрузкой, где читаемость важнее скорости.
    

### 3. XML-RPC

![6](https://github.com/ShAmRoWw/articles/blob/main/article_rpc/6.png)

- Один из старейших форматов, использующий XML для обмена данными.
    
- Устаревший, но всё ещё используется в некоторых системах из-за простой структуры и широкой поддержки.
    
- Менее эффективен из-за громоздкости XML и отсутствия современных оптимизаций.
    

### 4. Apache Thrift

- Разработан в Facebook. Поддерживает различные протоколы и форматы передачи данных.
    
- Предоставляет инструменты генерации кода для множества языков.
    
- Используется в распределённых системах с высоким уровнем взаимодействия между сервисами.
    

## Применение RPC в реальных проектах

### 1. Микросервисы

В архитектуре микросервисов, когда десятки и сотни компонентов должны быстро и эффективно обмениваться данными, RPC (особенно gRPC) идеально подходит. Он позволяет строго определить API, обеспечить высокую скорость и типовую совместимость между сервисами.

### 2. Взаимодействие клиент-сервер

Многие мобильные и десктопные приложения используют RPC для обращения к backend-сервисам. Например, в финтех-приложениях можно использовать gRPC для моментального получения информации о транзакциях.

### 3. Облачные и распределённые системы

Платформы вроде Kubernetes, Istio и Envoy активно применяют RPC внутри своей инфраструктуры. gRPC, благодаря производительности и поддержке потоков, стал стандартом в экосистеме облачных решений.

### 4. IoT и встраиваемые системы

Из-за ограничения ресурсов и требований к скорости, встраиваемые системы часто используют бинарные RPC-протоколы для минимизации объёма передаваемых данных.

# 5. RPC в Active Directory

![7](https://github.com/ShAmRoWw/articles/blob/main/article_rpc/7.png)

**Active Directory (AD)** — это централизованная служба каталогов от Microsoft, используемая в доменных сетях для управления пользователями, компьютерами, группами и политиками безопасности. Одним из ключевых механизмов взаимодействия внутри AD является протокол **RPC**, обеспечивающий обмен данными между клиентами и контроллерами домена.

## 1. Почему Active Directory использует RPC

RPC в Active Directory используется для:

- удалённого вызова сервисов на контроллере домена (DC),
    
- репликации данных между контроллерами,
    
- взаимодействия инструментов администрирования (например, `Active Directory Users and Computers`) с сервером,
    
- удалённого управления службами и политиками.
    

RPC предоставляет надёжный механизм передачи вызовов, который обеспечивает согласованность и точность обмена данными между узлами сети.

## 2. Используемые порты и протоколы

Active Directory применяет **динамические порты RPC**:

- Стартовая инициализация происходит через **порт 135 (TCP)** — **Endpoint Mapper (EPM)**.
    
- После этого сервер и клиент договариваются о **динамическом порте**, обычно в диапазоне **49152–65535** (в Windows Server 2008 и новее).
    

Важно: при настройке межсетевых экранов (firewall) и NAT RPC может вызывать сложности из-за непредсказуемости портов.

## 3. Примеры сервисов AD, использующих RPC

- **Remote Procedure Call Locator (RpcSs)** — базовая служба RPC.
    
- **Netlogon** — обеспечивает аутентификацию пользователей и компьютеров.
    
- **Distributed File System (DFS)** — репликация и доступ к папкам.
    
- **Group Policy (GPO)** — передача политик клиентским машинам.
    
- **Active Directory Replication Service** — синхронизация данных между контроллерами.
    

Эти компоненты критически зависят от надёжного функционирования RPC.

## 4. Проблемы и диагностика RPC в AD

Наиболее частые проблемы с RPC в AD связаны с:

- блокировкой портов брандмауэром,
    
- нестабильной сетью (особенно при межсайтовом взаимодействии),
    
- сбоями служб RPC или зависимыми от них сервисами.
    

Инструменты для диагностики:

- `dcdiag /test:RPC`
    
- `nltest /dsgetdc:domain`
    
- Журналы событий Windows (`eventvwr.msc`) → **System / Directory Service**
    

## 5. Безопасность и защита RPC в AD

Поскольку RPC используется для чувствительных операций (аутентификация, репликация, управление политиками), Microsoft реализует:

- **Шифрование RPC** с использованием Kerberos и NTLM;
    
- **Аутентификацию на уровне канала** (RPC Security Context);
    
- Поддержку **RPC over HTTPS (RPC Proxy)** для защищённой работы через интернет (например, в Exchange или Outlook Anywhere);
    
- Возможность **ограничения диапазона портов** для RPC через групповые политики и реестр — важный шаг в конфигурации безопасной сети.
    

# Заключение

Протокол удалённого вызова процедур (RPC) — это важный инструмент в арсенале разработчика распределённых систем. Он позволяет упростить взаимодействие между компонентами, скрывая сложную сетевую логику за привычным интерфейсом вызова функций. Современные реализации, такие как gRPC, значительно расширили возможности классического RPC, обеспечив высокую производительность, поддержку потоков и кросс-языковую интеграцию.

RPC активно применяется в микросервисной архитектуре, облачных платформах, IoT и особенно в корпоративных решениях, таких как Active Directory, где от него зависит множество критически важных служб. Несмотря на свои преимущества, RPC требует внимательного подхода к безопасности, обработке ошибок и мониторингу, чтобы избежать проблем в продакшене.

