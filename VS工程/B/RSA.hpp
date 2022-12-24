#pragma once
#pragma warning(disable:4996)
#pragma warning(disable:26451)
#pragma warning(disable:6387)
#include <string>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
//����ֵ��RSA���ܺ������
std::string rsa_pri_encrypt(const unsigned char* plain, size_t inlen, RSA* rsa)
{
    std::string strRet;

    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    // ����  
    int ret = RSA_private_encrypt(inlen, plain, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, ret);
    else
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), (char*)encryptedText));
    }
    // �ͷ��ڴ�  
    free(encryptedText);

    return strRet;
}

//��Կ����
std::string rsa_pub_encrypt(const unsigned char* plain, size_t inlen, RSA* rsa)
{
    std::string strRet;

    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    // ����  
    int ret = RSA_public_encrypt(inlen, plain, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, encryptedText + ret);
    else
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), (char*)encryptedText));
    }

    // �ͷ��ڴ�  
    free(encryptedText);

    return strRet;
}

// ��Կ����    
//���ؽ��ܺ������
std::string rsa_pub_decrypt(const unsigned char* cipher, size_t inlen, RSA* rsa)
{
    std::string strRet;

    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    //����
    int ret = RSA_public_decrypt(inlen, cipher, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, encryptedText + ret);
    else
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), (char*)encryptedText));
    }
    // �ͷ��ڴ�  
    free(encryptedText);

    return strRet;
}
//˽Կ����
std::string rsa_pri_decrypt(const unsigned char* cipher, size_t inlen, RSA* rsa)
{
    std::string strRet;


    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    //����
    int ret = RSA_private_decrypt(inlen, cipher, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, ret);
    else
    {
        printf("%s\n", ERR_error_string(ERR_get_error(), (char*)encryptedText));
    }
    // �ͷ��ڴ�  
    free(encryptedText);

    return strRet;
}

