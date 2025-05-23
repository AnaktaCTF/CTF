# Протокол SMTP. Как отправляются электронные письма и как они могут быть перехвачены

![image](https://github.com/user-attachments/assets/95a32ce1-ee3b-476b-af2a-455d06fb1140)

SMTP (Simple Mail Transfer Protocol) — это протокол, который используется для передачи электронной почты между клиентами и серверами. Он играет ключевую роль в механизме отправки писем в интернете. Хотя большинство пользователей никогда не задумываются о том, как работает отправка сообщений, протокол SMTP является основой всей почтовой системы. Знание того, как работает SMTP и как можно эксплуатировать его уязвимости, является важным для специалистов в области кибербезопасности, особенно в контексте задач на соревнованиях по информационной безопасности (CTF).

## Как работает SMTP?

Когда пользователь отправляет электронное письмо через почтовый клиент или веб-интерфейс, происходит несколько шагов. Протокол SMTP передает письмо от одного сервера к другому. Этот процесс выглядит следующим образом:

1. Почтовый клиент подключается к SMTP-серверу, используя стандартный порт 25 (или 465, 587 для защищенных соединений).

2. Клиент передает серверу информацию о том, кто является отправителем письма (команда *MAIL FROM*), кому оно адресовано (команда *RCPT TO*), а затем передает тело письма (команда *DATA*).

3. После того как сервер получает данные, он либо сохраняет письмо для последующей доставки получателю, если он обслуживается на этом же сервере, либо пересылает его на почтовый сервер получателя.

SMTP работает с текстовыми командами, которые легко читаются и понимаются. Например, при подключении к серверу через командную строку с помощью утилиты *telnet*, можно вручную отправить письмо, используя стандартные текстовые команды. Сначала устанавливается соединение, затем сервер приветствует клиента, и тот отправляет команды, указывая отправителя, получателя и содержание письма. После того как письмо передано, сессия завершается.

![image](https://github.com/user-attachments/assets/321d330a-084a-4112-bdd8-1f9bd5f9daf0)

## Уязвимости SMTP

SMTP, несмотря на свою функциональность, был разработан в эпоху, когда безопасность не была на первом месте. Поэтому в старых версиях протокола нет встроенного шифрования или обязательной аутентификации, что делает его уязвимым для атак. Одной из таких уязвимостей является *open relay*.

**Open relay** — это сервер, который разрешает пересылку писем от любого отправителя к любому получателю без авторизации. Это означает, что злоумышленники могут использовать этот сервер для рассылки спама или фальшивых писем от имени другого человека. В случае, если сервер не настроен должным образом, любой пользователь может отправить электронное письмо с любым адресом отправителя, что приводит к подделке электронной почты.

Другой важной уязвимостью является отсутствие шифрования в старых версиях SMTP. Если сервер не поддерживает защиту канала связи (например, через TLS или STARTTLS), данные, передаваемые между клиентом и сервером, могут быть перехвачены. В трафике, который передается в открытом виде, могут содержаться конфиденциальные данные, такие как логины и пароли, адреса отправителя и получателя, а также содержимое самого письма. Это открывает возможности для перехвата информации злоумышленникам

## Анализ сетевого трафика

*SMTP* — текстовый протокол, что означает, что все передаваемые данные можно легко проанализировать. Для этого используется специальное ПО, например, Wireshark. Если сервер SMTP не использует шифрование, то всё, что передается между клиентом и сервером, можно увидеть в захваченном сетевом трафике.

С помощью Wireshark можно открыть .pcap файл, содержащий сетевой трафик, и увидеть все команды SMTP. Например, можно найти команды MAIL FROM, RCPT TO, а также данные о содержимом письма. Если в письме содержится флаг (например, в рамках задания CTF), его можно обнаружить прямо в теле письма. Более того, если используется незащищенная авторизация, логины и пароли также можно увидеть в открытом виде.

SMTP часто используется в задачах CTF, связанных с анализом почтового трафика или отправкой писем от имени других пользователей. В таких задачах участникам может быть предложено:

1. Отправить письмо через уязвимый SMTP-сервер, который не требует аутентификации.

2. Перехватить и проанализировать сетевой трафик, чтобы извлечь полезную информацию или флаг.

3. Подделать письмо с фальшивым отправителем, чтобы обмануть систему.

Такие задания требуют не только знаний теории, но и практических навыков работы с инструментами для анализа трафика и взаимодействия с почтовыми серверами. В процессе решения таких задач важно понимать, как работает SMTP, какие уязвимости могут быть использованы, и как можно перехватить и проанализировать данные, передаваемые через этот протокол.

## SMTP и социальная инженерия

Хотя SMTP — это технический протокол передачи электронной почты, он очень часто используется как канал для социальной инженерии — формы атаки, при которой злоумышленник воздействует на человека, а не на машину. Используя особенности и уязвимости SMTP, атакующий может создать видимость доверенного сообщения, чтобы обмануть получателя.

## Как SMTP способствует атакам социальной инженерии?

SMTP по своей природе не проверяет, действительно ли отправитель является тем, за кого себя выдает. Это означает, что без дополнительных механизмов защиты (SPF, DKIM, DMARC) любой человек может отправить письмо от имени другого пользователя или домена. Например, злоумышленник может написать письмо, которое будет выглядеть так, будто оно пришло от службы поддержки банка или внутреннего отдела компании.

Такое письмо может содержать:

1. Поддельные предупреждения о «подозрительной активности»;

2. Просьбы срочно подтвердить логин и пароль;

3. Ссылки на фишинговые сайты;

Инструкции на перевод денег или открытие вложения (в котором вирус).

### Почему такие атаки работают?

SMTP по умолчанию не проверяет отправителя — без SPF/DKIM любой может подделать поле "From".

Люди доверяют внешнему виду письма — особенно, если используются логотипы, официальный стиль и грамотный русский язык.

Многие почтовые клиенты не показывают технические заголовки — и человек просто не видит, что письмо пришло с подозрительного сервера.

Спешка, страх или авторитет — стандартные триггеры социальной инженерии. Если письмо пугает ("доступ будет заблокирован") или навязывает авторитет ("директор требует перевода"), у жертвы меньше шансов критически оценить его.

## Защита SMTP

С развитием технологий безопасности SMTP был дополнен средствами защиты. Современные почтовые серверы используют методы аутентификации, такие как проверка логинов и паролей, чтобы предотвратить несанкционированную отправку писем. Кроме того, технологии шифрования (например, STARTTLS) защищают данные от перехвата.

Для защиты от подделки отправителя используются технологии, такие как SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail) и DMARC (Domain-based Message Authentication, Reporting & Conformance). Эти технологии позволяют почтовым серверам проверять, является ли отправитель авторизованным для использования конкретного домена.

![image](https://github.com/user-attachments/assets/f3834f9e-70de-4261-bf34-96c91d81d7ee)

![image](https://github.com/user-attachments/assets/04f4f681-ed6d-48bd-afae-c4611dbfe9a9)

Тем не менее, многие старые и неправильно настроенные серверы до сих пор остаются уязвимыми. Поэтому важно всегда проверять настройки безопасности SMTP-серверов и использовать современные методы защиты для предотвращения атак.
_________________
**SMTP** — это важный и широко используемый протокол, который лежит в основе отправки электронной почты. Несмотря на свою простоту, он содержит ряд уязвимостей, которые могут быть использованы злоумышленниками для подделки писем, рассылки спама или перехвата данных. Знание этих уязвимостей важно для специалистов по безопасности, поскольку это помогает не только в защите информационных систем, но и в участии в задачах CTF. Кроме того, понимание принципов работы SMTP и его защиты помогает эффективно анализировать сетевой трафик и работать с почтовыми серверами на более глубоком уровне.
