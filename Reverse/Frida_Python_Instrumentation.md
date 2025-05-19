# Динамическая инструментализация приложений с помощью Frida и Python

Динамическая инструментализация — это метод исследования поведения приложений во время их выполнения, позволяющий разработчику или исследователю вмешиваться в работу целевой программы, перехватывать вызовы функций, модифицировать данные и собирать внутреннюю информацию. Одним из самых мощных и гибких инструментов для динамической инструментализации является **Frida** — мультиплатформенная библиотека с открытым исходным кодом, позволяющая создавать скрипты на JavaScript для внедрения в процесс цели. В сочетании с Python она становится не просто средством анализа, но и полноценной платформой автоматизации реверс-инжиниринга и пентестинга.

В этой статье мы подробно разберём, как настраивать окружение для работы с Frida и Python, как писать Frida-скрипты на JavaScript для перехвата вызовов функций, изменять аргументы и возвращаемые значения «на лету», обходить certificate pinning и другие антидебаг-механизмы, а также как с помощью обёрток на Python собирать секреты — пароли, токены и криптографические ключи — и сохранять их в файлы для последующего анализа. Для каждого шага мы приведём примеры кода и пошаговые инструкции, чтобы вы могли повторить весь процесс самостоятельно.



## 1. Подготовка окружения

Перед тем как погружаться в написание скриптов, необходимо настроить рабочую среду. Мы будем работать на одной из платформ: Linux, Windows, Android или iOS. Универсальный рецепт следующий:

1. Установить **Python 3.7+**.
2. Установить пакетный менеджер **pip** (обычно входит в дистрибутив Python).
3. Установить **Frida-Tools** и **Frida**-библиотеки для Python.

Пример установки под Linux (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install python3 python3-pip
pip3 install frida-tools frida
```

Для Windows достаточно загрузить установщик Python с официального сайта, убедиться, что опция установки pip активирована, далее в командной строке:

```powershell
pip install frida-tools frida
```

Чтобы взаимодействовать с мобильными приложениями на Android, потребуется установить **ADB** (Android Debug Bridge) и включить отладку по USB на устройстве. Для iOS предлагает использовать **Frida Gadget** или **USBMuxListener** и **iproxy**, однако в большинстве случаев достаточно Frida-server.

После установки убедитесь, что Frida доступна из командной строки:

```bash
frida-ps -U   # Список процессов на подключённом Android-устройстве
frida-ps     # Список локальных процессов на ПК
```

Если вы видите список процессов, окружение настроено правильно.



## 2. Базовые концепции Frida

Frida работает по принципу «внедрения» (injection). Она предоставляет:

* **frida-server** — демон, запускаемый на целевом устройстве или в контейнере, принимающий подключения от клиента;
* **Frida-CLI (frida)** — утилита для подключения и загрузки JavaScript-скриптов в целевой процесс;
* **Frida Python API** — позволяет автоматизировать подключение к процессу, загрузку скриптов, обмен сообщениями.

При загрузке скрипта Frida вставляет свой рантайм (Frida Gadget) в адресное пространство процесса и запускает ваш JavaScript-код в контексте приложения. С помощью API JavaScript вы можете:

* находить модули и адреса функций (`Module.findExportByName`, `Module.enumerateExportsSync`);
* создавать `Interceptor` для перехвата функций и замены их поведения;
* отправлять сообщения из JavaScript в Python и обратно (`send()`, `on('message')`);
* выполнять асинхронные и синхронные операции внутри процесса.



## 3. Первое подключение и простейший перехват

### 3.1. JavaScript-скрипт

Напишем самый простой JavaScript для перехвата функции `open` в libc (либо `CreateFileW` в Windows). Скрипт будет логировать путь к открытому файлу.

```javascript
// hook_open.js
const openPtr = Module.findExportByName(null, "open");
if (openPtr) {
    Interceptor.attach(openPtr, {
        onEnter: function (args) {
            this.path = args[0].readUtf8String();
            console.log("[*] open called with path:", this.path);
        },
        onLeave: function (retval) {
            console.log("[*] open returned", retval.toInt32());
        }
    });
} else {
    console.error("Unable to find open()");
}
```

### 3.2. Запуск из командной строки

Подключимся к локальному процессу по его PID (предположим, PID = 1234):

```bash
frida -p 1234 -l hook_open.js
```

После запуска утилита `frida` выведет лог при каждом вызове `open`, показывая путь. Это простой способ убедиться, что инструмент работает.

## 4. Обёртка на Python для автоматизации

Хотя Frida-CLI удобна для быстрых проверок, при серийных запусках и сборе данных стоит воспользоваться Python API. Создадим скрипт `instrument.py`, который:

1. Подключается к целевому процессу (локальному или удалённому).
2. Загружает JS-скрипт.
3. Обрабатывает сообщения от Frida.
4. Сохраняет результаты в файл.

```python
# instrument.py
import frida
import sys
import json
from datetime import datetime

LOG_FILE = "frida_log.jsonl"

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            **payload
        }
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        print("[+] Logged:", payload)
    else:
        print(message)

def main():
    if len(sys.argv) != 3:
        print("Usage: python instrument.py <process> <script.js>")
        sys.exit(1)

    process = sys.argv[1]
    script_path = sys.argv[2]
    
    # Выбор подключения: локальное или USB-устройство Android
    if process.isdigit():
        session = frida.attach(int(process))
    else:
        session = frida.get_usb_device().attach(process)
    
    with open(script_path) as f:
        script_source = f.read()
    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()
    
    print("[*] Instrumentation active. Press Ctrl+C to quit.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
```

Пояснения:

* `get_usb_device()` возвращает первый доступный Android-устройство через ADB;
* все сообщения от JS-скрипта мы предполагаем отправлять через `send({ ... })`;
* результаты сохраняются в `frida_log.jsonl` как JSON Lines: каждый объект на отдельной строке.

Запуск:

```bash
python3 instrument.py com.target.app hook_open.js
```

## 5. Перехват и модификация аргументов и возвращаемых значений

Иногда нужно не только логировать, но и изменять поведение функций. Рассмотрим сценарий, когда приложение проверяет лицензию с помощью функции `check_license(user_id, key)`, возвращающую `true` либо `false`.

### 5.1. Скрипт для обхода проверки лицензии

```javascript
// bypass_license.js
const moduleName = "liblicense.so"; // имя модуля на Android
const funcName = "check_license";
const funcPtr = Module.findExportByName(moduleName, funcName);

Interceptor.attach(funcPtr, {
    onEnter: function (args) {
        // Здесь можно посмотреть аргументы, например:
        const uid = args[0].readUtf8String();
        console.log("[*] check_license called for user:", uid);
    },
    onLeave: function (retval) {
        // Изменяем возвращаемое значение на true
        retval.replace(1);
        console.log("[*] check_license bypassed, returned true");
    }
});
```

Если вместо POSIX-функции используется C++-метод, необходимо сначала найти сигнатуру функции в экспортах или использовать `Module.enumerateSymbolsSync` с фильтрацией по имени.

### 5.2. Пример изменения аргумента

Предположим, есть функция `encrypt(data, length)` и мы хотим заменить первые байты данных на нули.

```javascript
// patch_encrypt.js
const encryptPtr = Module.findExportByName(null, "encrypt");
Interceptor.attach(encryptPtr, {
    onEnter: function (args) {
        const buf = args[0];
        const len = args[1].toInt32();
        console.log("[*] encrypt called, length:", len);
        // Обнуляем первые 16 байт
        Memory.protect(buf, len, 'rw-');
        for (let i = 0; i < Math.min(16, len); i++) {
            buf.add(i).writeU8(0);
        }
        console.log("[*] first 16 bytes zeroed");
    }
});
```

Скрипт перезаписывает буфер до передачи его в оригинальную функцию `encrypt`, таким образом модифицируя данные на лету.

## 6. Обход Certificate Pinning и антидебаг-механизмов

Современные приложения часто используют certificate pinning, чтобы предотвратить перехват HTTPS-трафика. Frida с помощью JavaScript может патчить классы и методы на уровне SSL-библиотек или JNI-слоёв в Android и iOS.

### 6.1. Android (Java-пиннинг)

Пример для Android, где перехватывается класс `javax.net.ssl.X509TrustManager`:

```javascript
// android_ssl_bypass.js
Java.perform(function () {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkServerTrusted.implementation = function (chain, authType) {
        console.log("[*] checkServerTrusted called, bypassing SSL pinning");
        // ничего не делать — считаем сертификат доверенным
    };
});
```

Если приложение использует **OkHttp**, можно перехватить метод `CertificatePinner.check()`:

```javascript
Java.perform(function () {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peerCertificates) {
        console.log("[*] OkHttp certificate pinning bypassed for host:", host);
    };
});
```

### 6.2. iOS (Objective-C)

На iOS перехват методов реализован через `ObjC`:

```javascript
// ios_ssl_bypass.js
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var delegate = NSURLSession.delegate;
    // Перехватываем метод URLSession:didReceiveChallenge:completionHandler:
    ObjC.classes.NSURLSession.prototype['URLSession:didReceiveChallenge:completionHandler:'].implementation = function (session, challenge, handler) {
        console.log("[*] SSL challenge received, bypassing");
        var credential = ObjC.classes.NSURLCredential.credentialForTrust(challenge.protectionSpace().serverTrust());
        handler(challenge, 1, credential);
    };
}
```

Таким образом, мы при каждом SSL-челлендже автоматически принимаем сертификат, обходя pining.

## 7. Антидебаг и защита от отладки

Некоторые приложения проверяют наличие отладчика или сторонних фреймворков. Frida позволяет патчить такие проверки, например, для функции `ptrace` на Linux/Android:

```javascript
// disable_ptrace.js
const ptrace = Module.findExportByName("libc.so", "ptrace");
Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
    console.log("[*] ptrace hooked, returning 0");
    return 0; // Возвращаем успех вместо ошибки
}, 'int', ['int', 'int', 'pointer', 'pointer']));
```

Это позволяет обойти проверки, которые приложения выполняют для обнаружения инструментариев или отладчиков.

## 8. Сбор и сохранение секретов

Чтобы получить токены, пароли или криптографические ключи, нужно найти функции, где они генерируются или используются, и перехватить их аргументы или возвращаемое значение.

### 8.1. Пример перехвата пароля

Допустим, приложение вызывает функцию `char* get_password()`. Напишем скрипт:

```javascript
// capture_password.js
const getPasswordPtr = Module.findExportByName(null, "get_password");
Interceptor.attach(getPasswordPtr, {
    onLeave: function (retval) {
        var pwd = retval.readUtf8String();
        send({ type: "password", value: pwd });
        console.log("[*] Captured password:", pwd);
    }
});
```

В Python-обёртке `on_message` мы получаем объект с `{ type: "password", value: "..." }` и сохраняем в JSONL.

### 8.2. Пример перехвата токена из HTTP-запроса

Если приложение формирует HTTP-запрос через библиотеку, например, `curl_easy_perform`, можно перехватить функцию отправки заголовков:

```javascript
// capture_token.js
const CURLOPT_HTTPHEADER = 10023; // код опции
const curl_easy_setopt = Module.findExportByName("libcurl.so", "curl_easy_setopt");
Interceptor.attach(curl_easy_setopt, {
    onEnter: function (args) {
        if (args[1].toInt32() === CURLOPT_HTTPHEADER) {
            var headers = args[2];
            // headers — указатель на struct curl_slist
            // Проходим по списку и читаем заголовки
            var ptr = headers;
            while (!ptr.isNull()) {
                var line = ptr.readPointer().readUtf8String();
                if (line.indexOf("Authorization:") !== -1) {
                    send({ type: "token", value: line });
                }
                // Переходим к next
                ptr = ptr.add(Process.pointerSize).readPointer();
            }
        }
    }
});
```

## 9. Комбинирование нескольких скриптов и динамическая загрузка

Иногда нужно комбинировать скрипты в один модуль или динамически загружать фрагменты кода. Frida позволяет загружать несколько скриптов через Python:

```python
# multi_instrument.py (фрагмент)
scripts = ["bypass_license.js", "android_ssl_bypass.js", "capture_password.js"]
for path in scripts:
    with open(path) as f:
        module = session.create_script(f.read())
        module.on('message', on_message)
        module.load()
```

Также внутри JavaScript можно загружать динамические модули с помощью `Module.load()` и `Process.getModuleByName()`, что особенно полезно для плагинов или библиотек.

## 10. Практический пример: анализ Android-приложения

Рассмотрим полный пример анализа Android-приложения с пакетом `com.example.app`. Цель — перехватить проверку лицензии и собрать токен аутентификации.

1. **Запустить frida-server** на эмуляторе или устройстве:

   ```bash
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
   ```

2. **Создать JavaScript-файл** `analysis.js` со следующим содержимым:

   ```javascript
   Java.perform(function () {
       // Пиннинг SSL
       var CertPinner = Java.use('okhttp3.CertificatePinner');
       CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, certs) {
           console.log("[*] SSL bypass for host:", host);
       };
       
       // Проверка лицензии
       var LicenseMgr = Java.use('com.example.app.LicenseManager');
       LicenseMgr.isLicensed.implementation = function () {
           console.log("[*] isLicensed called, returning true");
           return true;
       };

       // Перехват токена
       var Auth = Java.use('com.example.app.network.AuthService');
       Auth.getToken.implementation = function () {
           var token = this.getToken();
           send({ type: 'token', value: token });
           return token;
       };
   });
   ```

3. **Написать Python-обёртку** `run_analysis.py` по аналогии с предыдущим скриптом `instrument.py`.

4. **Запустить скрипт**:

   ```bash
   python3 run_analysis.py com.example.app analysis.js
   ```

   В консоли вы увидите логи о bypass SSL, обходе лицензии и сообщения вида:

   ```
   [+] Logged: {'type': 'token', 'value': 'eyJhbGciOiJIUzI1Ni...'}
   ```

5. **Анализ результатов**. Откройте `frida_log.jsonl`, отфильтруйте по ключу `token`.

## 11. Советы и рекомендации

* **Поиск экспорта**. Если вы не знаете точного имени функции, используйте `Module.enumerateExportsSync(moduleName)` и фильтруйте по части имени.
* **Обход обфускации**. Модные сборщики могут переименовывать методы; в этом случае ищите «сусликов» (англ. monkey patching) через динамическое сканирование памяти или сигнатурный поиск (AOB scan).
* **Производительность**. Не используйте слишком частые операции в `onEnter`, чтобы не замедлять приложение. Для долгих вычислений лучше передавать данные в Python.
* **Защита от обнаружения**. Некоторые приложения могут заметить Frida по наличию символов или заголовков. Можно «затушевать» Gadget, изменить имя процесса или инжектить библиотеку вручную.
* **Совместимость**. Убедитесь, что версии Frida на ПК и на устройстве совпадают; иначе возможны ошибки несовместимости протокола.

## Заключение

Динамическая инструментализация с помощью Frida и Python открывает бескрайние возможности для анализа, тестирования и исследования приложений. Вы научились:

* настраивать окружение под Linux, Windows, Android и iOS;
* писать Frida-скрипты на JavaScript для перехвата и модификации функций;
* автоматизировать процесс с помощью обёрток на Python;
* обходить certificate pinning и антидебаг-механизмы;
* собирать пароли, токены и ключи для последующего исследования.

Теперь вы можете адаптировать эти примеры под любые приложения, расширять функциональность скриптов и автоматизировать сложные задачи реверс-инжиниринга. Frida в связке с Python становится не просто инструментом, а настоящей платформой, позволяющей изучать внутреннее устройство самых защищённых программ «на лету».
