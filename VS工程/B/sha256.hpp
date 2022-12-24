#pragma once
#include <openssl/sha.h>
#include <string>
#include "RSA.hpp"
std::string sha256(const std::string str);
std::string Signate(std::string src_data, RSA* rsa_prikey);
std::string sha256(const std::string str)
{
    char buf[2];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    return std::string(hash, hash + SHA256_DIGEST_LENGTH);
}

//Éú³ÉÇ©Ãû
std::string Signate(std::string src_data, RSA* rsa_prikey)
{
    std::string sha = sha256(src_data);
    std::string sig = rsa_pri_encrypt((const unsigned char*)sha.data(), sha.size(), rsa_prikey);
    return sig;
}