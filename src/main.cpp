#include "utils/utils.h"

void testEncryptionFunctions() {
    std::string originalText = "Yep";
    std::string password = "your_password_here";

    std::string encodedText = b64encode(originalText);
    std::string decodedText = b64decode(encodedText);

    std::string sha256Hash = sha256(originalText);

    std::vector<unsigned char> plaintextBytes(originalText.begin(), originalText.end());
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    genKeyIvbyStr(password, key, iv);

    std::vector<unsigned char> ciphertext = aesEncrypt(plaintextBytes, key, iv);
    std::vector<unsigned char> decryptedText = aesDecrypt(ciphertext, key, iv);

    std::cout << "Original: " << originalText << std::endl;

    std::cout << "Encrypted: ";
    printHex(std::cout, ciphertext);
    std::cout << std::endl;

    std::cout << "Decrypted: ";
    printRaw(std::cout, decryptedText);
    std::cout << std::endl;

    std::cout << "SHA-256: " << sha256Hash << std::endl;
    std::cout << "Base64 Encoded: " << encodedText << std::endl;
    std::cout << "Base64 Decoded: " << decodedText << std::endl;

    std::cout << "Key: ";
    printHex(std::cout, key);
    std::cout << std::endl;

    std::cout << "IV: ";
    printHex(std::cout, iv);
    std::cout << std::endl;

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

int main() {
    testEncryptionFunctions();

    return 0;
}