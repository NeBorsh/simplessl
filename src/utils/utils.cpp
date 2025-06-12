#include "utils.h"

void handleErr() {
    ERR_print_errors_fp(stderr);
    abort();
}

std::ostream& printHex(std::ostream& os, const std::vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return os;
}

std::ostream& printRaw(std::ostream& os, const std::vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        os << byte;
    }
    return os;
}

std::vector<unsigned char> genRandKey(int keyLen) {
    std::vector<unsigned char> key(keyLen);
    if (RAND_bytes(key.data(), keyLen) != 1) {
        handleErr();
    }
    return key;
}

std::vector<unsigned char> genRandIV(int ivLen) {
    std::vector<unsigned char> iv(ivLen);
    if (RAND_bytes(iv.data(), ivLen) != 1) {
        handleErr();
    }
    return iv;
}

std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErr();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        handleErr();
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int ciphertextLength = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertextLength, plaintext.data(), plaintext.size()) != 1) {
        handleErr();
    }

    int finalCipherTextLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLength, &finalCipherTextLen) != 1) {
        handleErr();
    }

    ciphertext.resize(ciphertextLength + finalCipherTextLen);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErr();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        handleErr();
    }
    
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int plaintextLen = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &plaintextLen, ciphertext.data(), ciphertext.size()) != 1) {
        handleErr();
    }

    int finalPlaintextLen = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLen, &finalPlaintextLen) != 1) {
        handleErr();
    }

    plaintext.resize(plaintextLen + finalPlaintextLen);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

std::string sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string b64encode(const std::string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);

    std::string encoded(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return encoded;
}

std::string b64decode(const std::string& input) {
    BIO *bio, *b64;
    
    char *buffer = new char[input.size()];
    size_t length = input.size();
    
    bio = BIO_new_mem_buf(input.data(), length);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    int decodedLen = BIO_read(bio, buffer, length);
    if (decodedLen < 0) {
        delete[] buffer;
        BIO_free_all(bio);
        handleErr();
    }
    
    std::string result(buffer, decodedLen);
    delete[] buffer;
    BIO_free_all(bio);
    
    return result;
}

void genKeyIvbyStr(const std::string& password, std::vector<unsigned char>& key, std::vector<unsigned char>& iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    key.assign(hash, hash + 32);

    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    iv.assign(hash, hash + 16);
}

void generateRSAKeyPair(const std::string &publicKeyFile, const std::string &privateKeyFile) {
    BIGNUM *bn = BN_new();
    if (!bn || !BN_set_word(bn, RSA_F4)) {
        handleErr();
    }

    RSA *rsaKeyPair = RSA_new();
    if (!rsaKeyPair || !RSA_generate_key_ex(rsaKeyPair, 2048, bn, nullptr)) {
        handleErr();
    }

    FILE *publicKeyFilePtr = fopen(publicKeyFile.c_str(), "wb");
    if (!publicKeyFilePtr || !PEM_write_RSA_PUBKEY(publicKeyFilePtr, rsaKeyPair)) {
        handleErr();
    }
    fclose(publicKeyFilePtr);

    FILE *privateKeyFilePtr = fopen(privateKeyFile.c_str(), "wb");
    if (!privateKeyFilePtr || !PEM_write_RSAPrivateKey(privateKeyFilePtr, rsaKeyPair, nullptr, nullptr, 0, nullptr, nullptr)) {
        handleErr();
    }
    fclose(privateKeyFilePtr);

    RSA_free(rsaKeyPair);
    BN_free(bn);
}

RSA* loadPublicKey(const std::string& publicKeyFile) {
    FILE *publicKeyFilePtr = fopen(publicKeyFile.c_str(), "rb");
    if (!publicKeyFilePtr) {
        handleErr();
    }
    RSA *publicKey = PEM_read_RSA_PUBKEY(publicKeyFilePtr, nullptr, nullptr, nullptr);
    fclose(publicKeyFilePtr);
    return publicKey;
}

RSA* loadPrivateKey(const std::string& privateKeyFile) {
    FILE *privateKeyFilePtr = fopen(privateKeyFile.c_str(), "rb");
    if (!privateKeyFilePtr) {
        handleErr();
    }
    RSA *privateKey = PEM_read_RSAPrivateKey(privateKeyFilePtr, nullptr, nullptr, nullptr);
    fclose(privateKeyFilePtr);
    return privateKey;
}

std::vector<unsigned char> rsaEncrypt(const std::vector<unsigned char>& plaintext, RSA* publicKey) {
    int rsaLen = RSA_size(publicKey);
    std::vector<unsigned char> ciphertext(rsaLen);

    int resultLen = RSA_public_encrypt(plaintext.size(), plaintext.data(), ciphertext.data(), publicKey, RSA_PKCS1_OAEP_PADDING);
    if (resultLen == -1) {
        handleErr();
    }
    ciphertext.resize(resultLen);

    return ciphertext;
}

std::vector<unsigned char> rsaDecrypt(const std::vector<unsigned char>& ciphertext, RSA* privateKey) {
    int rsaLen = RSA_size(privateKey);
    std::vector<unsigned char> plaintext(rsaLen);

    int resultLen = RSA_private_decrypt(ciphertext.size(), ciphertext.data(), plaintext.data(), privateKey, RSA_PKCS1_OAEP_PADDING);
    if (resultLen == -1) {
        handleErr();
    }
    plaintext.resize(resultLen);

    return plaintext;
}