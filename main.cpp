#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <random>

using namespace std;
using namespace std::chrono;

const int ROUNDS = 27; // Количество раундов для SPECK64/128
using u64 = uint64_t;
using u32 = uint32_t;

// Функция побитового сдвига вправо
u64 rotate_right(u64 x, int r) {
    return (x >> r) | (x << (64 - r));
}

// Функция побитового сдвига влево
u64 rotate_left(u64 x, int r) {
    return (x << r) | (x >> (64 - r));
}

// Функция шифрования для одного блока
void encrypt(u64& left, u64& right, const vector<u64>& round_keys) {
    for (int i = 0; i < ROUNDS; ++i) {
        left = (rotate_right(left, 8) + right) ^ round_keys[i];
        right = rotate_left(right, 3) ^ left;
    }
}

// Функция расшифровки для одного блока
void decrypt(u64& left, u64& right, const vector<u64>& round_keys) {
    for (int i = ROUNDS - 1; i >= 0; --i) {
        right = rotate_right(right ^ left, 3);
        left = rotate_left((left ^ round_keys[i]) - right, 8);
    }
}

// Генерация круглых ключей
vector<u64> key_schedule(const vector<u64>& key) {
    vector<u64> round_keys(ROUNDS);
    u64 b = key[0];
    vector<u64> a = {key[1], key[2], key[3]};
    round_keys[0] = b;

    for (int i = 0; i < ROUNDS - 1; ++i) {
        a[i % 3] = (rotate_right(a[i % 3], 8) + b) ^ i;
        b = rotate_left(b, 3) ^ a[i % 3];
        round_keys[i + 1] = b;
    }
    return round_keys;
}

// Функция для генерации случайного 128-битного ключа
vector<u64> generate_random_key() {
    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<u64> dis(0, UINT64_MAX);

    vector<u64> key(4);
    for (int i = 0; i < 4; ++i) {
        key[i] = dis(gen);
    }
    return key;
}

// Разбиение текста на части, кратные 16 байтам (128 бит)
string pad_text(const string& text) {
    string padded_text = text;
    size_t padding_needed = 16 - (text.size() % 16);
    if (padding_needed < 16) {
        padded_text.append(padding_needed, ' ');
    }
    return padded_text;
}

// Шифрование длинного текста в режиме ECB
string encrypt_text(const string& text, const vector<u64>& round_keys) {
    string padded_text = pad_text(text);
    string encrypted_text;

    for (size_t i = 0; i < padded_text.size(); i += 16) {
        u64 left = *reinterpret_cast<const u64*>(padded_text.data() + i);
        u64 right = *reinterpret_cast<const u64*>(padded_text.data() + i + 8);
        encrypt(left, right, round_keys);

        encrypted_text.append(reinterpret_cast<char*>(&left), 8);
        encrypted_text.append(reinterpret_cast<char*>(&right), 8);
    }

    return encrypted_text;
}

// Дешифрование длинного текста с помощью режима ECB
string decrypt_text(const string& text, const vector<u64>& round_keys) {
    string decrypted_text;

    for (size_t i = 0; i < text.size(); i += 16) {
        u64 left = *reinterpret_cast<const u64*>(text.data() + i);
        u64 right = *reinterpret_cast<const u64*>(text.data() + i + 8);
        decrypt(left, right, round_keys);

        decrypted_text.append(reinterpret_cast<char*>(&left), 8);
        decrypted_text.append(reinterpret_cast<char*>(&right), 8);
    }

    return decrypted_text;
}

// Преобразование шестнадцатеричной строки в вектор 64-битных целых чисел
vector<u64> hex_to_key(const string& hex) {
    vector<u64> key(4);
    for (int i = 0; i < 4; ++i) {
        key[i] = stoull(hex.substr(i * 16, 16), nullptr, 16);
    }
    return key;
}

// Вывод данных в шестнадцатеричном формате
void print_hex(const string& text) {
    for (unsigned char c : text) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
}

// Вывод 64-битных частей ключа в шестнадцатеричном формате
void print_key(const vector<u64>& key) {
    for (const auto& k : key) {
        cout << hex << setw(16) << setfill('0') << k;
    }
}

int main() {
    while (true) {
        cout << "Choose an option:\n1. Encrypt text\n2. Decrypt text\n3. Exit\n";
        int choice;
        cin >> choice;
        cin.ignore(); // Игнорирование символа новой строки после выбора

        if (choice == 1) {
            // Режим шифрования
            vector<u64> key = generate_random_key();
            auto round_keys = key_schedule(key);

            cout << "Enter text to encrypt: ";
            string text;
            getline(cin, text);

            auto start = high_resolution_clock::now();
            string encrypted_text = encrypt_text(text, round_keys);
            auto end = high_resolution_clock::now();

            cout << "\nEncrypted text (hex): ";
            print_hex(encrypted_text);
            cout << "\nGenerated key (hex): ";
            print_key(key);

            cout << "\nEncryption time: " << duration_cast<nanoseconds>(end - start).count() << " nanoseconds\n";

        } else if (choice == 2) {
            // Режим дешифрования
            cout << "Enter encrypted text (hex): ";
            string hex_text;
            cin >> hex_text;

            string encrypted_text;
            for (size_t i = 0; i < hex_text.length(); i += 2) {
                string byte = hex_text.substr(i, 2);
                encrypted_text.push_back(static_cast<char>(stoi(byte, nullptr, 16)));
            }

            cout << "Enter key (16 bytes in hex, 32 hex characters): ";
            string hex_key;
            cin >> hex_key;

            auto key = hex_to_key(hex_key);
            auto round_keys = key_schedule(key);

            string decrypted_text = decrypt_text(encrypted_text, round_keys);
            cout << "\nDecrypted text: " << decrypted_text << endl;

        } else if (choice == 3) {
            break; // Выход из программы
        } else {
            cout << "Invalid choice. Please try again.\n";
        }

        cout << "\n"; // Добавление новой строки для лучшей читабельности
    }

    return 0;
}
