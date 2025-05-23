# Стеганография в изображении

**Стеганография** — это способ спрятать информацию внутри другой информации или физического объекта так, чтобы ее нельзя было обнаружить. 
С помощью стеганографии можно спрятать практически любой цифровой контент, включая тексты, изображения, аудио- и видеофайлы. 
А когда эта спрятанная информация поступает к адресату, ее извлекают. (https://www.kaspersky.ru/)

### Разница между стеганографией и криптографией  
Основные различия между этими методами защиты информации:  

| Характеристика  | Стеганография  | Криптография  |
|---------------|--------------|--------------|
| Основной принцип  | Скрытие существования информации | Шифрование информации |
| Выявляемость  | Трудно обнаружить без специализированных методов анализа  | Видно, что данные зашифрованы |
| Безопасность  | Основана на незаметности | Основана на математической стойкости алгоритмов |
| Защита от модификации  | Уязвима при малейшем изменении контейнера | Алгоритмы обеспечивают целостность данных |
| Применение  | Водяные знаки, защита информации, сокрытие данных | Шифрованная переписка, защита файлов, цифровые подписи |

Оба метода можно комбинировать: сначала зашифровать данные, а затем скрыть их с помощью стеганографии, что значительно повышает безопасность передаваемой информации.  

### Области применения  
Стеганография находит применение в различных сферах:  

1. **Защита конфиденциальных данных** — скрытая передача информации в условиях цензуры или наблюдения.  
2. **Цифровые водяные знаки** — защита авторских прав на изображения, видео и аудиофайлы.  
3. **Кибербезопасность** — скрытая коммуникация между агентами, обход контроля трафика.  
4. **Военные и разведывательные операции** — скрытая передача секретных сообщений.  
5. **Компьютерные игры и ARG (Alternative Reality Games)** — создание скрытых посланий и головоломок.  

## История стеганографии  

### Древние методы скрытия информации  
Идея скрытия информации появилась задолго до появления цифровых технологий. Несколько известных исторических методов:  

- **Голая кожа (V век до н.э.)** — греческий полководец Гистией в условиях персидского контроля выбрил голову слуги, написал на коже тайное послание и дождался, пока волосы отрастут.  
- **Невидимые чернила (I век н.э.)** — использовались в Древнем Риме и Средневековье. Для письма применяли лимонный сок или молоко, проявлявшиеся при нагревании.  
- **Микротекст** — в XIX веке в письмах использовали мельчайший шрифт, чтобы спрятать информацию в безобидных письмах или книгах.  
- **Татуировки и узоры** — в XVII–XIX веках моряки иногда наносили татуировки с закодированными сообщениями для передачи секретной информации.  

### Развитие методов в цифровую эпоху  
С появлением компьютеров и интернета стеганография получила новый виток развития:  

- **1990-е** — Разработка первых цифровых методов, таких как изменение наименее значащих битов (LSB) в изображениях.  
- **2000-е** — Появление алгоритмов, использующих преобразования (DCT, DWT, FFT), что позволило более эффективно скрывать данные.  
- **2010-е** — Развитие машинного обучения, позволяющего как создавать более сложные методы скрытия, так и выявлять их.  
- **Настоящее время** — Интеграция стеганографии в защиту авторских прав, информационную безопасность и скрытые коммуникации.  

Стеганография продолжает развиваться, оставаясь важным инструментом в мире цифровой безопасности.  

# Основные методы стеганографии в изображениях

## Метод наименее значащих битов (LSB)
### Принцип работы
Метод LSB (Least Significant Bit) основан на изменении младших битов цветовых компонентов пикселей изображения. Поскольку изменения в младших битах незначительно влияют на визуальное восприятие, скрытая информация остаётся незаметной для человеческого глаза.

### Как это работает?
1. Берётся исходное изображение (контейнер).
2. Бинарное представление скрываемых данных заменяет младшие биты цветовых каналов (обычно RGB).
3. Полученное изображение сохраняется, и оно визуально неотличимо от оригинала.

**Пример:**
- Исходный пиксель: `10110011 01101110 11001001` (RGB)
- Кодируем символ "A" (ASCII: `01000001`)
- Заменяем младшие биты: `10110010 01101111 11001000`

### Преимущества
- Простота реализации.
- Минимальное визуальное искажение.

### Недостатки
- Легко обнаруживается при стегоанализе.
- Уязвимость к сжатию и обработке изображений.

## Получение exif файлов

EXIF - это информация, записываемая в файл снимка большинством цифровых фотокамер, и содержащая тестовую информацию: дата и время съемки, модель камеры, съёмочные параметры 
(выдержка, баланс белого, фокусное расстояние, вспышка, источник света, диафрагма, цифровое увеличение), комментарий к файлу, авторские права и т.д. 
(https://help.inbox.lv/category/10085/question/10255?language=ru)

Как пример, можно узнать место, в котором был сделан снимок:

![](https://github.com/AnaktaCTF/CTFReports/blob/main/e1409/pictures/ct1.jpg)

![](https://github.com/AnaktaCTF/CTFReports/blob/main/e1409/pictures/ct2.png)

Узнаем, что снимок был сделан по адресу Place des Capucines, Belsunce, Marseille 1er Arrondissement, Марсель, Marseille, Буш-дю-Рон, Прованс — Альпы — Лазурный Берег, Метрополия Франции, 13001, Франция.

(задание с сайта root-me.org EXIF-Metadata)


## Методы преобразования (DCT, DWT, FFT)
Методы, основанные на преобразованиях, внедряют данные в частотные компоненты изображения, что делает их более устойчивыми к сжатию и обработке.

### **DCT (Discrete Cosine Transform, дискретное косинусное преобразование)**
Используется в JPEG-сжатии. В скрытом сообщении изменяются частотные коэффициенты после DCT, что позволяет сохранить информацию даже при сжатии JPEG.

### **DWT (Discrete Wavelet Transform, дискретное вейвлет-преобразование)**
Позволяет внедрять данные в многомасштабные представления изображения, что делает метод более устойчивым к атакам стегоанализа.

### **FFT (Fast Fourier Transform, быстрое преобразование Фурье)**
Применяет частотный анализ для встраивания данных в малозаметные компоненты изображения.

### Преимущества методов преобразования:
- Высокая устойчивость к сжатию.
- Трудность обнаружения скрытых данных.

### Недостатки:
- Сложность реализации.
- Требуется больше вычислительных ресурсов.

## Альфа-канал стеганография
### Принцип работы
Использует канал прозрачности (альфа-канал) изображений PNG для скрытия информации. Поскольку альфа-канал регулирует степень прозрачности пикселей, его изменение не всегда заметно глазу.

### Как работает?
1. В альфа-канале внедряется двоичный код скрытых данных.
2. Значения прозрачности слегка корректируются, чтобы избежать визуального обнаружения.
3. Восстановление информации возможно только при анализе альфа-канала.

### Преимущества
- Высокая скрытность.
- Устойчивость к изменению цветовых данных.

### Недостатки
- Работает только с изображениями, поддерживающими альфа-канал (PNG, TIFF).
- Некоторые программы могут преобразовывать PNG в формат без альфа-канала, уничтожая скрытые данные.

Работа с изображениями с помощью Stegsolve 

Для Windows ОС необходимо установить http://www.caesum.com/handbook/Stegsolve.jar и Java Runtime Environment

Для Linux ОС https://github.com/zardus/ctf-tools/blob/master/stegsolve/install

С помощью Stegsolve можно посмотреть формат файла

![](https://github.com/AnaktaCTF/CTFReports/blob/main/e1409/pictures/ct3.png)

Разные планы файла 

![](https://github.com/AnaktaCTF/CTFReports/blob/main/e1409/pictures/ct4.png)

Открыть несколько изображений и посмотреть из наложения:

![](https://github.com/AnaktaCTF/CTFReports/blob/main/e1409/pictures/ct5.png)

Посмотреть режимы файла

![](https://github.com/AnaktaCTF/CTFReports/blob/main/e1409/pictures/ct6.png)

## Использование шумов и артефактов сжатия
### Принцип работы
Метод использует естественные шумы или артефакты сжатия (например, JPEG) для скрытия данных. Данные внедряются в шумовые компоненты, что делает их менее заметными.

### Реализация
1. Анализируются шумовые характеристики изображения.
2. В шумовые области внедряются скрытые данные.
3. Изменения распределяются случайным образом, что затрудняет обнаружение.

### Преимущества
- Высокая скрытность.
- Устойчивость к обработке изображений.

### Недостатки
- Трудность извлечения информации без оригинального изображения.
- Зависимость от характеристик контейнера.

### Изображение-архив

Изображение может оказаться архивом. Обычно это заметно, если фото весит больше, чем должно весить при таких размерах.

Обычно алгоритм работы такой: 

1. Изменить тип файла (например сменить окончание .png на .zip или любой другой тип архива)
2. Разорхивировать файл
3. Открыть файлы архива, в зависимости от ситуации можно сразу найти флаг или применить другие методы
   

## Обзор инструментов

### **StegHide**
StegHide — это один из популярных инструментов для скрытия данных в изображениях. Он использует метод наименее значащих битов (LSB) для внедрения информации в пиксели изображений. StegHide поддерживает различные форматы файлов, включая BMP, WAV и другие.

**Пример использования StegHide:**

```bash
steghide embed -cf image.png -ef secret.txt
```

Эта команда скрывает содержимое файла `secret.txt` в изображении `image.png`.

### **OpenStego**
OpenStego — это открытый инструмент, который также использует метод LSB для скрытия данных. Он позволяет не только скрывать информацию, но и защищать её с помощью пароля, обеспечивая дополнительную безопасность.

**Пример использования OpenStego:**

```bash
java -jar OpenStego.jar embed -sf image.png -ef secret.txt -p password
```

Здесь изображение `image.png` скрывает текстовый файл `secret.txt` с паролем `password`.

### **SilentEye**
SilentEye — это еще один инструмент для скрытия информации в изображениях и аудиофайлах. Он предоставляет графический интерфейс и позволяет легко спрятать данные в разных форматах изображений, таких как PNG, JPEG, BMP.

**Пример использования SilentEye:**

1. Откройте SilentEye.
2. Выберите изображение, в которое хотите вставить данные.
3. Загрузите файл с информацией, которую хотите скрыть.
4. Установите пароль для защиты скрытой информации.
5. Нажмите "Embed", чтобы сохранить изображение с скрытой информацией.

## Пример реализации на Python

В Python можно использовать библиотеки, такие как Pillow или OpenCV, для реализации стеганографии. Рассмотрим пример, как скрыть текст в изображении с использованием библиотеки Pillow:

```python
from PIL import Image

def encode_image(image_path, message):
    img = Image.open(image_path)
    binary_message = ''.join(format(ord(i), '08b') for i in message)
    binary_message += '1111111111111110'  # Добавляем окончание сообщения
    pixels = img.load()

    data_index = 0
    for y in range(img.height):
        for x in range(img.width):
            pixel = list(pixels[x, y])
            for color in range(3):  # RGB
                if data_index < len(binary_message):
                    pixel[color] = pixel[color] & ~1 | int(binary_message[data_index])
                    data_index += 1
            pixels[x, y] = tuple(pixel)
            if data_index >= len(binary_message):
                break

    img.save('encoded_image.png')
    print("Image encoded successfully.")

def decode_image(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    binary_message = ""
    
    for y in range(img.height):
        for x in range(img.width):
            pixel = pixels[x, y]
            for color in range(3):  # RGB
                binary_message += str(pixel[color] & 1)
    
    message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
    return message.split('1111111111111110')[0]  # Отделяем скрытое сообщение

# Пример использования:
encode_image('image.png', 'This is a hidden message.')
decoded_message = decode_image('encoded_image.png')
print("Decoded message:", decoded_message)
```

Этот пример показывает, как можно закодировать текстовое сообщение в изображение, а затем извлечь его обратно.

# Обнаружение стеганографии (стегоанализ)

## Методы выявления скрытых данных

1. **Анализ наименее значащих битов (LSB)**
   Метод LSB — один из самых простых и распространенных, и он также является самым уязвимым к стегоанализу. Для выявления скрытых данных можно анализировать статистику изменения пикселей и искать паттерны, характерные для использования LSB.

2. **Частотный анализ**
   Методы, такие как DCT, DWT или FFT, изменяют частотные компоненты изображения, что делает его менее заметным для человеческого глаза, но позволяет специалистам по стегоанализу обнаружить скрытые данные с помощью анализа изменений частот.

3. **Анализ сжатия**
   Данные, внедренные в изображение, могут быть уничтожены при сильном сжатии (например, JPEG), но иногда для анализа достаточно исследовать остаточные артефакты сжатия.

4. **Использование алгоритмов машинного обучения**
   Современные методы машинного обучения могут быть использованы для автоматического обнаружения скрытых данных. Например, нейронные сети могут быть обучены на изображениях с и без скрытых данных для выявления скрытых паттернов.

## Инструменты для анализа изображений

- **StegExpose** — это инструмент для анализа изображений на наличие скрытых данных, особенно в методах LSB.
- **zsteg** — инструмент для выявления скрытых данных в изображениях PNG и BMP, анализирует биты и частотные компоненты.
- **ImageMagick** — позволяет выполнить анализ и извлечение данных из изображений, а также обработку метаданных и альфа-каналов.

# Безопасность и этические аспекты

## Опасности скрытия информации

1. **Нарушение законов**
   Использование стеганографии для скрытия информации может быть нарушением законов, особенно в контексте киберпреступности, шпионажа или распространения запрещенного контента.

2. **Риски безопасности**
   Хотя стеганография может использоваться для защиты конфиденциальных данных, она также может стать инструментом для скрытых атак, распространения вирусов, троянов и шпионских программ.

3. **Ошибка в передаче**
   В некоторых случаях скрытые данные могут быть случайно повреждены или уничтожены, если изображение подвергается изменению (например, сжатию или редактированию).

## Использование в кибербезопасности и киберпреступности

- **Кибербезопасность**: Стеганография может использоваться для защиты данных, обеспечения конфиденциальности в условиях цензуры и мониторинга.
- **Киберпреступность**: Злоумышленники могут использовать стеганографию для скрытого обмена информацией, например, для управления ботнетами или для скрытого обмена файлами с вредоносным ПО.

# Заключение

## Будущее стеганографии
Стеганография продолжает развиваться, и с каждым годом она становится более устойчивой к различным методам анализа. В будущем можно ожидать появления новых методов, использующих более сложные математические алгоритмы и машинное обучение.

## Выводы и перспективы развития технологии

- **Повышение сложности скрытия данных**: Включение искусственного интеллекта и сложных алгоритмов шифрования сделает стеганографию ещё более эффективной.
- **Рост применения в цифровой безопасности**: Стеганография будет продолжать использоваться для защиты конфиденциальности данных и анонимности в интернете.
- **Этические и правовые вопросы**: Важно будет учитывать этические и правовые аспекты, связанные с использованием стеганографии, особенно в контексте киберпреступности и защиты прав интеллектуальной собственности.
