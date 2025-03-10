# Использование особенностей NTFS для сокрытия данных в Forensics-задачах

NTFS (New Technology File System) – это стандартная файловая система Windows, которая обладает множеством продвинутых функций, предназначенных для оптимизации работы системы и безопасности данных. Однако эти же функции можно использовать для сокрытия информации, что делает NTFS интересной мишенью в цифровой криминалистике (Forensics) и CTF-задачах.

![image](https://github.com/user-attachments/assets/48bf922c-7b29-449e-a864-95ca83666b99)


В Forensics-челленджах злоумышленник может спрятать файлы так, что они не будут видны стандартными средствами. Для поиска таких данных участникам приходится разбираться в особенностях NTFS и применять специализированные инструменты.

В этой статье мы разберем несколько техник сокрытия данных:

•	альтернативные потоки данных (ADS),

•	манипуляции с метаданными файлов,

•	использование скрытых NTFS-записей.
________________________________________

### Альтернативные потоки данных (NTFS Alternate Data Streams, ADS)

#### Что такое ADS?

**ADS** – это механизм NTFS, который позволяет привязывать дополнительные потоки данных к файлу без изменения его основного содержимого.

*Пример*:
Создадим обычный текстовый файл и спрячем в нем дополнительную информацию:

![image](https://github.com/user-attachments/assets/fbf00718-a2cf-4ddf-8a16-4d0e79af8cdd)

Теперь, если посмотреть на secret.txt в Проводнике или командной строке (dir), его размер останется неизменным. Однако скрытый поток данных hidden никуда не пропал.

### Как обнаружить и извлечь ADS?

Чтобы проверить, есть ли у файла скрытые потоки, используем:

![image](https://github.com/user-attachments/assets/6c982c86-37cc-4eda-a53b-bbd7d80ccf4d)
![image](https://github.com/user-attachments/assets/3123e4d2-38fa-4221-8d8d-0463d15258d3)


Для их извлечения можно использовать команду PowerShell:

![image](https://github.com/user-attachments/assets/c80dc1eb-c605-4794-81ff-dcf89cefbbfb)

#### Применение ADS в CTF-задачах
В CTF скрытые потоки часто используют для сокрытия флага. Например, организаторы могут спрятать flag.txt внутри README.md:

![image](https://github.com/user-attachments/assets/1388c0d8-5a5e-41da-9ec8-cd085112e7b8)

Чтобы найти флаг, участнику придется проверить ADS в файлах, которые кажутся бесполезными.
________________________________________

### Манипуляции с метаданными и скрытые файлы

#### Атрибуты файлов (Hidden, System, Read-Only)

В Windows файлы можно скрыть простыми атрибутами:

![image](https://github.com/user-attachments/assets/a8b67f12-c311-4b6e-85f6-54827177c0c0)

Такой файл не отобразится в Проводнике, если не включены скрытые элементы. Однако в CTF-задачах такие трюки легко обходятся через 

```attrib -s -h secret.txt.```

#### Скрытие данных в Master File Table (MFT) – Resident Files

**MFT** хранит метаданные файлов, но если файл маленький (например, несколько байт), его содержимое может быть сохранено прямо в записи MFT. Это позволяет спрятать данные в структуре NTFS без создания видимого файла.

##### Как проверить?

Используем:

![image](https://github.com/user-attachments/assets/21edc79c-1940-47fc-bd78-974930c70aa0)

Если файл "невидим", его можно вытащить с помощью утилит вроде $MFT parser.
________________________________________
### NTFS-записи и техники маскировки

#### Slack Space – остаточное пространство в кластерах

NTFS выделяет файлам кластеры фиксированного размера. Если файл занимает меньше места, чем кластер, в оставшемся пространстве могут оставаться данные от старых удаленных файлов. Это можно использовать для сокрытия данных.

#####Как найти Slack Space?

Используются криминалистические утилиты, такие как *Autopsy* или *FTK Imager*.

![image](https://github.com/user-attachments/assets/9abdde69-4330-4e89-b23e-6dd6091212af)
![image](https://github.com/user-attachments/assets/155efb95-73df-4d0a-9443-988c4920f0d4)

#### Жесткие ссылки (Hard Links) и Junction Points

В Windows можно создать жесткую ссылку, чтобы файл существовал в нескольких местах одновременно:

![image](https://github.com/user-attachments/assets/5b6813f2-b276-4a7a-a643-67b75b009785)

Файл new_file.txt и secret.txt указывают на одно и то же содержимое. Удаление одного файла не затронет второй. Это часто применяется для маскировки файлов.

**Junction Points** – это специальные символические ссылки на каталоги. Например, можно сделать скрытую ссылку на папку с важными файлами:

![image](https://github.com/user-attachments/assets/f950d069-717b-4e2a-a6a5-b793245d6411)
 
Обычные проверки dir или Проводник могут не показывать такие ссылки.
________________________________________

NTFS предоставляет мощные инструменты для хранения и организации данных, но они же могут быть использованы для скрытия информации.
Альтернативные потоки, скрытые файлы, манипуляции с MFT и Hard Links – важные техники, которые часто встречаются в CTF-задачах.
В реальной цифровой криминалистике их знание помогает расследовать инциденты, находить скрытые данные и бороться с киберпреступностью.

