#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <sstream>

using namespace std;

typedef unsigned char byte;

// Hộp thay thế AES (S-box)
const byte sBox[256] = {
    // Các giá trị trong hộp thay thế
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
// Bảng tham chiếu ngược của S-box
const byte InvSBox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// Mảng hằng số vòng
// Khai báo mảng Rcon
const byte Rcon[4][10] = {
    {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};


// Hàm mở rộng khóa (Key Expansion) trong AES
void KeyExpansion(const byte* key, byte* roundKeys) {
    const int Nb = 4; // Số cột trong trạng thái (state)
    const int Nk = 4; // Số cột trong khóa (key)
    const int Nr = 10; // Số vòng (rounds) trong AES-128

    byte temp[4]; // Mảng tạm

    // Copy 16 byte đầu tiên của khóa vào mảng roundKeys
    for (int i = 0; i < Nk * 4; ++i) {
        roundKeys[i] = key[i];
    }

    // Khởi tạo từ khóa cho các vòng tiếp theo
    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        for (int j = 0; j < 4; ++j) {
            temp[j] = roundKeys[(i - 1) * 4 + j];
        }

        if (i % Nk == 0) {
            // RotateWord
            byte tempByte = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = tempByte;

            // SubWord
            for (int j = 0; j < 4; ++j) {
                temp[j] = sBox[temp[j]];
            }

            // XOR với Rcon
            temp[0] ^= Rcon[0][i / Nk];
        }

        // XOR với từ khóa trước đó
        for (int j = 0; j < 4; ++j) {
            roundKeys[i * 4 + j] = roundKeys[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}


// Biến đổi SubBytes
void SubBytes(byte* state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sBox[state[i]];
    }
}

// Biến đổi ShiftRows
void ShiftRows(byte* state) {
    byte temp;

    // Row 1 không dịch chuyển
    // Row 2 dịch chuyển 1 byte sang trái
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 3 dịch chuyển 2 byte sang trái
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 4 dịch chuyển 3 byte sang trái
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}


// Hằng số cho biến đổi MixColumns
const byte MixColumnsMatrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};
// Hàm nhân trong trường hữu hạn của AES
byte Multiply(byte a, byte b) {
    byte result = 0;
    byte highBit;

    for (int i = 0; i < 8; ++i) {
        if ((b & 1) == 1) {
            result ^= a;
        }

        highBit = (byte)(a & 0x80);
        a <<= 1;
        if (highBit == 0x80) {
            a ^= 0x1B; // 00011011 là hằng số cho trường hữu hạn của AES
        }

        b >>= 1;
    }

    return result;
}


// Biến đổi MixColumns
void MixColumns(byte* state) {
    byte result[16];

    for (int col = 0; col < 4; ++col) {
        result[col * 4 + 0] = (byte)(Multiply(MixColumnsMatrix[0][0], state[col * 4 + 0]) ^ Multiply(MixColumnsMatrix[0][1], state[col * 4 + 1]) ^ Multiply(MixColumnsMatrix[0][2], state[col * 4 + 2]) ^ Multiply(MixColumnsMatrix[0][3], state[col * 4 + 3]));
        result[col * 4 + 1] = (byte)(Multiply(MixColumnsMatrix[1][0], state[col * 4 + 0]) ^ Multiply(MixColumnsMatrix[1][1], state[col * 4 + 1]) ^ Multiply(MixColumnsMatrix[1][2], state[col * 4 + 2]) ^ Multiply(MixColumnsMatrix[1][3], state[col * 4 + 3]));
        result[col * 4 + 2] = (byte)(Multiply(MixColumnsMatrix[2][0], state[col * 4 + 0]) ^ Multiply(MixColumnsMatrix[2][1], state[col * 4 + 1]) ^ Multiply(MixColumnsMatrix[2][2], state[col * 4 + 2]) ^ Multiply(MixColumnsMatrix[2][3], state[col * 4 + 3]));
        result[col * 4 + 3] = (byte)(Multiply(MixColumnsMatrix[3][0], state[col * 4 + 0]) ^ Multiply(MixColumnsMatrix[3][1], state[col * 4 + 1]) ^ Multiply(MixColumnsMatrix[3][2], state[col * 4 + 2]) ^ Multiply(MixColumnsMatrix[3][3], state[col * 4 + 3]));
    }

    // Sao chép kết quả vào trạng thái ban đầu
    for (int i = 0; i < 16; ++i) {
        state[i] = result[i];
    }
}

// Biến đổi AddRoundKey
void AddRoundKey(byte* state, const byte* roundKey) {
    // Thực hiện biến đổi AddRoundKey
    for (int i = 0; i < 16; ++i) {
        state[i] ^= roundKey[i];
    }
}

// Biến đổi InvShiftRows
void InvShiftRows(byte* state) {
    byte temp;

    // Dịch chuyển ngược lại cho các hàng
    // Row 1 không thay đổi
    // Row 2 dịch chuyển 1 byte sang phải
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Row 3 dịch chuyển 2 byte sang phải
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 4 dịch chuyển 3 byte sang phải
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// Biến đổi InvSubBytes
void InvSubBytes(byte* state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = InvSBox[state[i]];
    }
}
// Hàm nhân ngược trong trường hữu hạn của AES
byte InvMultiply(byte a, byte b) {
    byte result = 0;
    byte highBit;

    for (int i = 0; i < 8; ++i) {
        if ((b & 1) == 1) {
            result ^= a;
        }

        highBit = (byte)(a & 0x80);
        a <<= 1;
        if (highBit == 0x80) {
            a ^= 0x1B; // 00011011 là hằng số cho trường hữu hạn của AES
        }

        b >>= 1;
    }

    return result;
}


// Hằng số cho biến đổi InvMixColumns
const byte InvMixColumnsMatrix[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};

// Biến đổi InvMixColumns
void InvMixColumns(byte* state) {
    byte result[16];

    for (int col = 0; col < 4; ++col) {
        result[col * 4 + 0] = (byte)(InvMultiply(InvMixColumnsMatrix[0][0], state[col * 4 + 0]) ^ InvMultiply(InvMixColumnsMatrix[0][1], state[col * 4 + 1]) ^ InvMultiply(InvMixColumnsMatrix[0][2], state[col * 4 + 2]) ^ InvMultiply(InvMixColumnsMatrix[0][3], state[col * 4 + 3]));
        result[col * 4 + 1] = (byte)(InvMultiply(InvMixColumnsMatrix[1][0], state[col * 4 + 0]) ^ InvMultiply(InvMixColumnsMatrix[1][1], state[col * 4 + 1]) ^ InvMultiply(InvMixColumnsMatrix[1][2], state[col * 4 + 2]) ^ InvMultiply(InvMixColumnsMatrix[1][3], state[col * 4 + 3]));
        result[col * 4 + 2] = (byte)(InvMultiply(InvMixColumnsMatrix[2][0], state[col * 4 + 0]) ^ InvMultiply(InvMixColumnsMatrix[2][1], state[col * 4 + 1]) ^ InvMultiply(InvMixColumnsMatrix[2][2], state[col * 4 + 2]) ^ InvMultiply(InvMixColumnsMatrix[2][3], state[col * 4 + 3]));
        result[col * 4 + 3] = (byte)(InvMultiply(InvMixColumnsMatrix[3][0], state[col * 4 + 0]) ^ InvMultiply(InvMixColumnsMatrix[3][1], state[col * 4 + 1]) ^ InvMultiply(InvMixColumnsMatrix[3][2], state[col * 4 + 2]) ^ InvMultiply(InvMixColumnsMatrix[3][3], state[col * 4 + 3]));
    }

    // Sao chép kết quả vào trạng thái ban đầu
    for (int i = 0; i < 16; ++i) {
        state[i] = result[i];
    }
}

// Mã hóa AES
void EncryptAES(const byte* plainText, const byte* key, byte* cipherText) {
    const int Nr = 10; // Số lượng vòng (rounds) trong AES-128

    // Khởi tạo lịch khóa với khóa ban đầu
    byte roundKeys[176];
    KeyExpansion(key, roundKeys);

    // Sao chép văn bản thô vào trạng thái đầu tiên
    byte state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = plainText[i];
    }

    // Thực hiện các vòng mã hóa
    AddRoundKey(state, roundKeys); // Vòng khóa ban đầu
    for (int round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 16); // Vòng khóa cuối cùng

    // Sao chép trạng thái đã mã hóa vào văn bản mã hóa đầu ra
    for (int i = 0; i < 16; ++i) {
        cipherText[i] = state[i];
    }
}
// Giải mã AES
void DecryptAES(const byte* cipherText, const byte* key, byte* plainText) {
    const int Nr = 10; // Số lượng vòng (rounds) trong AES-128

    // Khởi tạo lịch khóa với khóa ban đầu
    byte roundKeys[176];
    KeyExpansion(key, roundKeys);

    // Sao chép văn bản mã hóa vào trạng thái đầu tiên
    byte state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = cipherText[i];
    }

    // Thực hiện các vòng giải mã
    AddRoundKey(state, roundKeys + Nr * 16); // Vòng khóa cuối cùng
    for (int round = Nr - 1; round > 0; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys); // Vòng khóa ban đầu

    // Sao chép trạng thái đã giải mã vào văn bản thô đầu ra
    for (int i = 0; i < 16; ++i) {
        plainText[i] = state[i];
    }
}


int main() {
    const string inputFile = "input.txt";
    const string encryptedFile = "encrypted.txt";
    const string decryptedFile = "decrypted.txt";
    const string keyFile = "key.txt";

    // Đọc khóa từ file
    string key;
    ifstream keyFileInput(keyFile);
    if (!keyFileInput) {
        cerr << "Lỗi khi mở file khóa." << endl;
        return 1;
    }
    getline(keyFileInput, key);
    keyFileInput.close();

    // Mở file đầu vào để đọc văn bản thô
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "Lỗi khi mở file đầu vào." << endl;
        return 1;
    }

    // Đọc dữ liệu từ file đầu vào vào vector<byte>
    vector<byte> plaintext((istreambuf_iterator<char>(inFile)), (istreambuf_iterator<char>()));
    inFile.close();

    // Mã hóa văn bản thô
    vector<byte> ciphertext(plaintext.size());
    EncryptAES(plaintext.data(), reinterpret_cast<const byte*>(key.c_str()), ciphertext.data());

    // Ghi dữ liệu đã mã hóa vào file
    ofstream outFile(encryptedFile, ios::binary);
    if (!outFile) {
        cerr << "Lỗi khi mở file đã mã hóa." << endl;
        return 1;
    }
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    outFile.close();

    // Đọc dữ liệu đã mã hóa từ file
    ifstream encryptedFileInput(encryptedFile, ios::binary);
    if (!encryptedFileInput) {
        cerr << "Lỗi khi mở file đã mã hóa." << endl;
        return 1;
    }
    vector<byte> encrypted((istreambuf_iterator<char>(encryptedFileInput)), (istreambuf_iterator<char>()));
    encryptedFileInput.close();

    // Giải mã dữ liệu đã mã hóa
    vector<byte> decrypted(encrypted.size());
    DecryptAES(encrypted.data(), reinterpret_cast<const byte*>(key.c_str()), decrypted.data());

    // Ghi dữ liệu đã giải mã vào file
    ofstream decryptedFileStream(decryptedFile, ios::binary);
    if (!decryptedFileStream) {
        cerr << "Lỗi khi mở file đã giải mã." << endl;
        return 1;
    }
    decryptedFileStream.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    decryptedFileStream.close();
    cout << "Mã hóa và giải mã thành công." << endl;
    return 0;
}
