#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <random>

using namespace std;
using namespace std::chrono;

const int ROUNDS = 27; // Number of rounds for SPECK64/128
using u64 = uint64_t;
using u32 = uint32_t;

// Function for rotating bits to the right
u64 rotate_right(u64 x, int r) {
    return (x >> r) | (x << (64 - r));
}

// Function for rotating bits to the left
u64 rotate_left(u64 x, int r) {
    return (x << r) | (x >> (64 - r));
}

// Encryption function for a single block
void encrypt(u64& left, u64& right, const vector<u64>& round_keys) {
    for (int i = 0; i < ROUNDS; ++i) {
        left = (rotate_right(left, 8) + right) ^ round_keys[i];
        right = rotate_left(right, 3) ^ left;
    }
}

// Decryption function for a single block
void decrypt(u64& left, u64& right, const vector<u64>& round_keys) {
    for (int i = ROUNDS - 1; i >= 0; --i) {
        right = rotate_right(right ^ left, 3);
        left = rotate_left((left ^ round_keys[i]) - right, 8);
    }
}

// Round keys generation
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

// Function to generate a random 128-bit key
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

// Pad text to a multiple of 16 bytes (128 bits)
string pad_text(const string& text) {
    string padded_text = text;
    size_t padding_needed = 16 - (text.size() % 16);
    if (padding_needed < 16) {
        padded_text.append(padding_needed, ' ');
    }
    return padded_text;
}

// Encrypt a long text using ECB mode
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

// Decrypt a long text using ECB mode
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

// Convert hex string to a vector of 64-bit integers
vector<u64> hex_to_key(const string& hex) {
    vector<u64> key(4);
    for (int i = 0; i < 4; ++i) {
        key[i] = stoull(hex.substr(i * 16, 16), nullptr, 16);
    }
    return key;
}

// Print data in hexadecimal format
void print_hex(const string& text) {
    for (unsigned char c : text) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
}

// Print 64-bit key parts in hexadecimal format
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
        cin.ignore(); // Ignore the newline character after the choice

        if (choice == 1) {
            // Encryption mode
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
            // Decryption mode
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
            break; // Exit the program
        } else {
            cout << "Invalid choice. Please try again.\n";
        }

        cout << "\n"; // Add a newline for better readability
    }

    return 0;
}
