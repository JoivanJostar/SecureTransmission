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
static unsigned char g_key[AES_BLOCK_SIZE] = "1wradfr4e3fefef";//16字节的AES密钥
//读取PKCS1格式的公钥
RSA* getPubkey(std::string key_file_path)
{
    BIO* bf = nullptr;
    RSA* rsa_pubkey = RSA_new();
    bf = BIO_new_file(key_file_path.c_str(), "r");
    if (bf == nullptr)
    {
        cout << "读取文件" << key_file_path << "失败\n";
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
//读取PKCS1格式的私钥
RSA* getPrikey(std::string key_file_path)
{
    BIO* bf = nullptr;
    RSA* res_prikey = RSA_new();
    bf = BIO_new_file(key_file_path.c_str(), "r");
    if (bf == nullptr)
    {
        cout << "读取文件" << key_file_path << "失败\n";
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
    //初始化WinSocket
    cout << "初始化WinSocket.....\n";
    if (InitWinsock())
        cout << "WinSocket初始化成功" << endl;
    else
    {
        cout << "WinSocket初始化失败" << endl;
        return -1;
    }
    //获取A和B的RSA公钥
    BIO* bf = nullptr;
    RSA* rsa_pubkey_A = nullptr;
    RSA* rsa_pubkey_B = nullptr;
    RSA* rsa_prikey_A = nullptr;
    if ((rsa_pubkey_A = getPubkey("./RSAkey/Apubkey.pem")) == nullptr)
    {
        cout << "获取A的公钥失败\n";
        return 0;
    }
    if ((rsa_pubkey_B = getPubkey("./RSAkey/Bpubkey.pem")) == nullptr)
    {
        cout << "获取B的公钥失败\n";
        return 0;
    }
    //获取A的RSA私钥
    if ((rsa_prikey_A = getPrikey("./RSAkey/Aprikey.pem")) == nullptr)
    {
        cout << "获取A的私钥失败\n";
        return 0;
    }
    //和B创建TCP连接 B的地址为127.0.0.1: 54321
    int sockfd = 0;
    unsigned short port = 54321; //B的端口号
    char buff[4096] = { 0 };
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    serveraddr.sin_port = htons(port); //字节序转换 本地字节序转为网络字节序
    sockfd = socket(AF_INET, SOCK_STREAM, 0); //创建TCP链接Socket
    if (sockfd == -1) {
        cout << "创建Socket失败\n";
        return 0;
    }
    cout << "尝试和B建立连接\n";
    if (connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
        cout << "向B发起连接失败" << endl;
        return 0;
    }
    cout << "连接成功\n";

    //交换AES密钥
    //用B的公钥对AES密钥加密
    string key_cipher = rsa_pub_encrypt(g_key, AES_BLOCK_SIZE, rsa_pubkey_B);
    //获取数据签名
    string sig = Signate(key_cipher, rsa_prikey_A);
    //发送加密后的密钥
    send(sockfd, key_cipher.data(), key_cipher.size(), 0);
    //发送签名
    send(sockfd, sig.data(), sig.size(), 0);
    int nbytes = 0;
    if ((nbytes = recv(sockfd, buff, 4096, 0)) <= 0)
    {
        cout << "与B断开连接\n";
        return 0;
    }
    buff[nbytes] = 0;
    if (strcmp("ACK", buff) == 0)
    {
        cout << "密钥交换成功\n";
    }
    else
    {
        cout << "密钥交换失败\n";
        return 0;
    }

    //循环：A从终端输入信息，加密发送给B。
    while (true)
    {
        cout << endl;
        cout << "请输入要发送的明文: ";
        string plain;
        cin >> plain;
        //对明文进行PKCS7填充 向16字节对齐
        PKCS7_padding(plain);
        //进行AES-CBC模式加密
        const size_t buffer_len = plain.size();
        unsigned char* cipher_buffer = new unsigned char[buffer_len];//cipher_buffer存储AES加密结果
        memset(cipher_buffer, 0, buffer_len);
        aes128_encrypt((const unsigned char*)plain.data(), plain.size(), cipher_buffer, g_key);
        string cipher(cipher_buffer, cipher_buffer + buffer_len);
        delete[] cipher_buffer;
        //制作数字签名
        sig = Signate(cipher, rsa_prikey_A);
        //发送加密数据和签名
        send(sockfd, cipher.data(), cipher.size(), 0);
        send(sockfd, sig.data(), sig.size(), 0);
        cout << "发送成功" << endl;
        if ((nbytes = recv(sockfd, buff, 4096, 0)) <= 0 || strcmp(buff,"ACK")!=0)
        {
            cout << "与B断开连接\n";
            return 0;
        }
        cout << "进程B验证通过" << endl;
    }
    getchar();
}
