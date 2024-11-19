# [Как работает код:](#как-работает-код)

1. **Функция `expandKey` (расширение ключа):** 
    - Эта функция берет основной 128-битный ключ и генерирует из него набор "раундовых ключей".
    - Эти раундовые ключи используются на каждом этапе шифрования и расшифровки, чтобы сделать процесс более сложным и безопасным.
    - В процессе создания ключей применяются циклические сдвиги, сложение и XOR.
2. **Функция `encrypt` (шифрование):** 
    - Эта функция преобразует открытый текст в зашифрованный текст.
    - Текст делится на две части, которые многократно изменяются в каждом раунде с использованием раундовых ключей.
    - Она использует операции:
        - Сложение по модулю (для перемешивания данных).
        - Побитовые сдвиги (для запутывания порядка данных).
        - XOR (для внесения нелинейности).
    - После всех раундов две части объединяются в зашифрованный текст.
3. **Функция `decrypt` (расшифровка):** 
    - Эта функция делает обратное к шифрованию — преобразует зашифрованный текст обратно в исходный.
    - Она берет зашифрованный текст, делит его на две части и выполняет раунды операций в обратном порядке.
    - Используются те же раундовые ключи, но применяются в обратном порядке, чтобы восстановить оригинальные данные.
4. **Главная функция `main`:** 
    - Это интерфейс для пользователя.
    - Пользователь выбирает, **зашифровать** или **расшифровать** текст.
    - В зависимости от выбора, программа:
        - Берет текст и ключ (при расшифровке).
        - Вызывает соответствующую функцию (`encrypt` или `decrypt`).
    - Пользователь может повторить операцию сколько угодно раз, пока не выберет выход из программы.