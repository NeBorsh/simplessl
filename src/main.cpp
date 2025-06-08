#include "utils/utils.h"

void testEncryptionFunctions() {
    std::string originalText = "Yep";

    std::string encodedText = b64encode(originalText);
    std::string decodedText = b64decode(encodedText);

    std::string sha256Hash = sha256(originalText);

    std::vector<unsigned char> plaintextBytes(originalText.begin(), originalText.end());
    std::vector<unsigned char> key = genRandKey(32);
    std::vector<unsigned char> iv = genRandIV(16);
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

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}


int main() {
    testEncryptionFunctions();

    return 0;
}