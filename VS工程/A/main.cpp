#pragma warning(disable:4996)
#pragma warning(disable:26451)
#pragma warning(disable:6387)
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib, "Ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<string>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <Windows.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include "RSA.hpp"
#include "AES.hpp"
#include "sha256.hpp"
#include <fstream>
#include "winSockinit.hpp"

using namespace std;
static unsigned char g_key[AES_BLOCK_SIZE] = "1wradfr4e3fefef";//16�ֽڵ�AES��Կ
//��ȡPKCS1��ʽ�Ĺ�Կ
RSA* getPubkey(std::string key_file_path)
{
    BIO* bf = nullptr;
    RSA* rsa_pubkey = RSA_new();
    bf = BIO_new_file(key_file_path.c_str(), "r");
    if (bf == nullptr)
    {
        cout << "��ȡ�ļ�" << key_file_path << "ʧ��\n";
        return nullptr;
    }
    rsa_pubkey = PEM_read_bio_RSAPublicKey(bf, &rsa_pubkey, nullptr, nullptr);
    if (rsa_pubkey == nullptr)
    {
        char err[100] = { 0 };
        printf("%s\n", ERR_error_string(ERR_get_error(), (char*)err));
    }

    return rsa_pubkey;
}
//��ȡPKCS1��ʽ��˽Կ
RSA* getPrikey(std::string key_file_path)
{
    BIO* bf = nullptr;
    RSA* res_prikey = RSA_new();
    bf = BIO_new_file(key_file_path.c_str(), "r");
    if (bf == nullptr)
    {
        cout << "��ȡ�ļ�" << key_file_path << "ʧ��\n";
        return nullptr;
    }
    res_prikey = PEM_read_bio_RSAPrivateKey(bf, &res_prikey, nullptr, nullptr);
    if (res_prikey == nullptr)
    {
        char err[100] = { 0 };
        printf("%s\n", ERR_error_string(ERR_get_error(), (char*)err));
    }

    return res_prikey;
}
int main() {
    OpenSSL_add_all_algorithms();
    //��ʼ��WinSocket
    cout << "��ʼ��WinSocket.....\n";
    if (InitWinsock())
        cout << "WinSocket��ʼ���ɹ�" << endl;
    else
    {
        cout << "WinSocket��ʼ��ʧ��" << endl;
        return -1;
    }
    //��ȡA��B��RSA��Կ
    BIO* bf = nullptr;
    RSA* rsa_pubkey_A = nullptr;
    RSA* rsa_pubkey_B = nullptr;
    RSA* rsa_prikey_A = nullptr;
    if ((rsa_pubkey_A = getPubkey("./RSAkey/Apubkey.pem")) == nullptr)
    {
        cout << "��ȡA�Ĺ�Կʧ��\n";
        return 0;
    }
    if ((rsa_pubkey_B = getPubkey("./RSAkey/Bpubkey.pem")) == nullptr)
    {
        cout << "��ȡB�Ĺ�Կʧ��\n";
        return 0;
    }
    //��ȡA��RSA˽Կ
    if ((rsa_prikey_A = getPrikey("./RSAkey/Aprikey.pem")) == nullptr)
    {
        cout << "��ȡA��˽Կʧ��\n";
        return 0;
    }
    //��B����TCP���� B�ĵ�ַΪ127.0.0.1: 54321
    int sockfd = 0;
    unsigned short port = 54321; //B�Ķ˿ں�
    char buff[4096] = { 0 };
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    serveraddr.sin_port = htons(port); //�ֽ���ת�� �����ֽ���תΪ�����ֽ���
    sockfd = socket(AF_INET, SOCK_STREAM, 0); //����TCP����Socket
    if (sockfd == -1) {
        cout << "����Socketʧ��\n";
        return 0;
    }
    cout << "���Ժ�B��������\n";
    if (connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
        cout << "��B��������ʧ��" << endl;
        return 0;
    }
    cout << "���ӳɹ�\n";

    //����AES��Կ
    //��B�Ĺ�Կ��AES��Կ����
    string key_cipher = rsa_pub_encrypt(g_key, AES_BLOCK_SIZE, rsa_pubkey_B);
    //��ȡ����ǩ��
    string sig = Signate(key_cipher, rsa_prikey_A);
    //���ͼ��ܺ����Կ
    send(sockfd, key_cipher.data(), key_cipher.size(), 0);
    //����ǩ��
    send(sockfd, sig.data(), sig.size(), 0);
    int nbytes = 0;
    if ((nbytes = recv(sockfd, buff, 4096, 0)) <= 0)
    {
        cout << "��B�Ͽ�����\n";
        return 0;
    }
    buff[nbytes] = 0;
    if (strcmp("ACK", buff) == 0)
    {
        cout << "��Կ�����ɹ�\n";
    }
    else
    {
        cout << "��Կ����ʧ��\n";
        return 0;
    }

    //ѭ����A���ն�������Ϣ�����ܷ��͸�B��
    while (true)
    {
        cout << endl;
        cout << "������Ҫ���͵�����: ";
        string plain;
        cin >> plain;
        //�����Ľ���PKCS7��� ��16�ֽڶ���
        PKCS7_padding(plain);
        //����AES-CBCģʽ����
        const size_t buffer_len = plain.size();
        unsigned char* cipher_buffer = new unsigned char[buffer_len];//cipher_buffer�洢AES���ܽ��
        memset(cipher_buffer, 0, buffer_len);
        aes128_encrypt((const unsigned char*)plain.data(), plain.size(), cipher_buffer, g_key);
        string cipher(cipher_buffer, cipher_buffer + buffer_len);
        delete[] cipher_buffer;
        //��������ǩ��
        sig = Signate(cipher, rsa_prikey_A);
        //���ͼ������ݺ�ǩ��
        send(sockfd, cipher.data(), cipher.size(), 0);
        send(sockfd, sig.data(), sig.size(), 0);
        cout << "���ͳɹ�" << endl;
        if ((nbytes = recv(sockfd, buff, 4096, 0)) <= 0 || strcmp(buff,"ACK")!=0)
        {
            cout << "��B�Ͽ�����\n";
            return 0;
        }
        cout << "����B��֤ͨ��" << endl;
    }
    getchar();
}
