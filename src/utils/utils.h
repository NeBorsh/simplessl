#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <stdlib.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstddef>

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include <openssl/rand.h>

void handleErr();
void genKeyIvbyStr(const std::string& password, std::vector<unsigned char>& key, std::vector<unsigned char>& iv);
void generateRSAKeyPair(const std::string& publicKeyFile, const std::string& privateKeyFile);

std::ostream& printHex(std::ostream& os, const std::vector<unsigned char>& data);
std::ostream& printRaw(std::ostream& os, const std::vector<unsigned char>& data);

RSA* loadPublicKey(const std::string& publicKeyFile);
RSA* loadPrivateKey(const std::string& privateKeyFile);

std::vector<unsigned char> genRandKey(int keyLen);
std::vector<unsigned char> genRandIV(int ivLen);
std::vector<unsigned char> rsaEncrypt(const std::vector<unsigned char>& plaintext, RSA* publicKey);
std::vector<unsigned char> rsaDecrypt(const std::vector<unsigned char>& ciphertext, RSA* privateKey);
std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& plaintext,
                                    const std::vector<unsigned char>& key,
                                    const std::vector<unsigned char>& iv);
std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& ciphertext, 
                                    const std::vector<unsigned char>& key, 
                                    const std::vector<unsigned char>& iv);

std::string sha256(const std::string str);
std::string b64encode(const std::string& input);
std::string b64decode(const std::string& input);