#pragma once
#pragma warning(disable:4996)
#pragma warning(disable:26451)
#pragma warning(disable:6387)
#include <openssl/aes.h>
#include <string>
int aes128_encrypt(const unsigned char* str_in, size_t inlen, unsigned char* out, unsigned char* key);
int aes128_decrypt(const unsigned char* str_in, size_t inlen, unsigned char* out, unsigned char* key);
int PKCS7_padding(std::string& src);
int PKCS7_unpadding(std::string& src);
//16字节的key 128bit


int aes128_encrypt(const unsigned char* str_in, size_t inlen, unsigned char* out, unsigned char* key)
{
    int i = 0;
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };
    if (!str_in || !out)
        return 0;
    for (i = 0; i < 16; ++i) //生成IV
        iv[i] = i + 32;
    if (AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0) {
        return 0;
    }
    AES_cbc_encrypt((unsigned char*)str_in, (unsigned char*)out, inlen, &aes, iv, AES_ENCRYPT);
    return 1;
}

int aes128_decrypt(const unsigned char* str_in, size_t inlen, unsigned char* out, unsigned char* key)
{
    int i = 0;
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };

    if (!str_in || !out)
        return -1;
    for (i = 0; i < 16; ++i)
        iv[i] = i + 32;

    if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
    {
        return -1;
    }

    AES_cbc_encrypt((unsigned char*)str_in, (unsigned char*)out, inlen, &aes, iv, AES_DECRYPT);
    return 0;
}

int PKCS7_padding(std::string& src) {

    char pad_char = 16-(src.size() % 16);
    for (int i = 0; i < pad_char; ++i)
    {
        src.push_back(pad_char);
    }
    return 1;
}
int PKCS7_unpadding(std::string& src)
{
    if (src.empty())
        return 0;
    char pad_char = src.back();
    for (int i = 0; i < pad_char; ++i)
    {
        if (src.empty())
            return 0;
        src.pop_back();
    }
    return 1;
}