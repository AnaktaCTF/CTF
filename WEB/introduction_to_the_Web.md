# Введение в Web-категорию CTF

## Оглавление
1. [Общая информация](#общая-информация)
2. [Простейший пример](#простейший-пример)
3. [С каких тем можно начать?](#с-каких-тем-можно-начать)
4. [Полезные материалы](#полезные-материалы)
5. [Сайты для тренировок](#сайты-для-тренировок)
6. [Использованные материалы](#использованные-материалы)

## Общая информация

Web - это одна из категорий тасков CTF, которая включает в себя:
- Анализ получаемых и передаваемых веб-приложению данных
- Поиск и эксплуатация уязвимостей различных веб-приложений
- Защита от уязвимостей
- Разнообразные методы взлома
- Веб-подмену информации
- Использование ошибок в настройке сервера

Примеры техник и атак:
- SQL-инъекции
- XSS-инъекции
- PHP-инъекции
- "Man-in-the-middle"
- "Meet-in-the-middle_attack"
- "Man-in-the-Browser"

Web - довольно обширная категория, охватывающая различные аспекты сетевой безопасности и взаимодействия через веб-интерфейс.

## Простейший пример

### DCTF 2021: Simple web (100 Points)

**Задание:** Time to warm up! http://dctf1-chall-simple-web.westeurope.azurecontainer.io:8080

**Решение** (от cieran / {The NaN Squad}, [источник](https://ctftime.org/writeup/28517)):

1. На странице показан чекбокс с надписью "Я хочу флаг!" и кнопка "Отправить".
2. Установка флажка и отправка возвращает "Not Authorized".
3. Анализ HTML кода:

![HTML код страницы](https://telegra.ph/file/cba07edfe516d33888b97.png)

4. В коде видно скрытое поле ввода с именем "auth" и значением 0.
5. Изменяем значения "auth" и "flag" на 1 и отправляем форму снова:

![Измененные значения полей](https://telegra.ph/file/48c13e8658687f8707e83.png)

После этого получаем флаг.

## С каких тем можно начать?

![Дерево знаний от SPbCTF](https://telegra.ph/file/b870b0a55324e708dff75.jpg)

## Полезные материалы

1. [SQL injection полный FAQ](https://rdot.org/forum/showthread.php?t=124)
2. [Что такое Топ-10 OWASP](https://telegra.ph/CHto-takoe-Top-10-OWASP-i-kakie-uyazvimosti-veb-prilozhenij-naibolee-opasny-10-04)
3. [Burp Suite](https://kmb.cybber.ru/web/burp/main.html)
4. [Cookie](https://kmb.cybber.ru/web/cookie/main.html)
5. [root-me.org "HTTP - Verb tampering" решение](https://internet-lab.ru/ctf_http_verb_tampering)
6. [Клиентская сторона JavaScript](https://wiki.cyberschool.msu.ru/wiki/%D0%92%D0%B5%D0%B1-%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D1%8C/%D0%9A%D0%BB%D0%B8%D0%B5%D0%BD%D1%82%D1%81%D0%BA%D0%B0%D1%8F_%D1%81%D1%82%D0%BE%D1%80%D0%BE%D0%BD%D0%B0_JavaScript)
7. [Уязвимости XSS](https://wiki.cyberschool.msu.ru/wiki/%D0%92%D0%B5%D0%B1-%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D1%8C/%D0%A3%D1%8F%D0%B7%D0%B2%D0%B8%D0%BC%D0%BE%D1%81%D1%82%D0%B8_XSS)
8. [Основы XML XXE](https://wiki.cyberschool.msu.ru/wiki/%D0%92%D0%B5%D0%B1-%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D1%8C/%D0%9E%D1%81%D0%BD%D0%BE%D0%B2%D1%8B_XML_XXE)
9. [Атаки SSRF](https://wiki.cyberschool.msu.ru/wiki/%D0%92%D0%B5%D0%B1-%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D1%8C/%D0%90%D1%82%D0%B0%D0%BA%D0%B8_SSRF)
10. [Сезон веба от SpbCTF (YouTube плейлист)](https://youtube.com/playlist?list=PLLguubeCGWoaGFEDzduGmBhEgZ62p-Jqv)

## Сайты для тренировок

1. [SQL Injection для новичков](https://www.alexbers.com/sql/) — челлендж от Александра Берсенёва
2. [Курс web от SPbCTF](https://web-kids20.forkbomb.ru/tasks)
3. [XSS Game](https://xss-game.appspot.com/) — игра от Google по поиску XSS-уязвимостей
4. [Hax.Tor.Hu](http://hax.tor.hu/welcome/)
5. В любом CTF присутствует категория Web

## Использованные материалы

- [KMB Cybber: Web](https://kmb.cybber.ru/web/main.html)
- [VK Album: CTF категории](https://vk.com/album-168686655_255109657)
- [CTFtime Writeup](https://ctftime.org/writeup/28517)
