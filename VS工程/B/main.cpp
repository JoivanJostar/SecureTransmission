#pragma warning(disable:4996)
#pragma warning(disable:26451)
#pragma warning(disable:6387)
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "Ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <string>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <Windows.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "RSA.hpp"
#include "AES.hpp"
#include "sha256.hpp"
#include <fstream>
#include "winSockinit.hpp"

using namespace std;
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
bool check_signature(string sig,RSA * rsa_pubkey,string cipher)
{
	//用A的公钥解密 获取签名的SHA256值 
	string src= rsa_pub_decrypt((const unsigned char *)sig.data(),sig.size(), rsa_pubkey);
	//本地计算一份密文的SHA256
	string expected = sha256(cipher);
	return src == expected;
}
int main()
{
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
	RSA* rsa_prikey_B = nullptr;
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
	//获取B的RSA私钥
	if ((rsa_prikey_B = getPrikey("./RSAkey/Bprikey.pem")) == nullptr)
	{
		cout << "获取B的私钥失败\n";
		return 0;
	}

	//绑定并监听端口，等待A连接
	unsigned short port = 54321; //B的端口号
	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//host ip addr

	int listensock = socket(AF_INET, SOCK_STREAM, 0);
	if (listensock == -1) {
		printf("创建Socket失败\n");
		exit(0);
	}
	char on = 1;
	//设置Socket为Reuse重用地址模式，这样能在重启进程时快速绑定成功
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	//绑定端口
	if (::bind(listensock, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
		printf("绑定端口失败，请检查端口%d是否被占用以及是否存在防火墙软件\n",port);
		exit(0);
	}
	//监听
	if (listen(listensock, 10) < 0) {
		printf("监听端口失败\n");
		exit(0);
	}
	cout << "进程B正在监听地址 127.0.0.1:" << port << endl;
	struct sockaddr_in clientaddr;
	::memset(&clientaddr, 0, sizeof(clientaddr));
	int addrlen = sizeof(clientaddr);
	int max_buffer_len = 1024 * 1024;
	int nbytes = 0;
	char* buffer = new char[max_buffer_len];
	memset(buffer, 0, max_buffer_len);
	for (;;) {
		cout << "等待A的连接......\n";
		//接受连接 3次握手
		int sockfd = accept(listensock, (struct sockaddr*)&clientaddr, &addrlen);
		cout << "接收到来自A的TCP连接" << endl;
		//交换密钥
		if((nbytes=recv(sockfd,buffer,max_buffer_len,0))<=0)
		{
			cout << "与A断开连接\n";
			closesocket(sockfd);
			continue;
		}
		string cipher(buffer, buffer + nbytes);
		string key = rsa_pri_decrypt((const unsigned char *)cipher.data(), cipher.size(), rsa_prikey_B);
		//验签
		if ((nbytes = recv(sockfd, buffer, max_buffer_len, 0)) <= 0)
		{
			cout << "与A断开连接\n";
			closesocket(sockfd);
			continue;
		}
		string sig(buffer, buffer + nbytes);
		if(check_signature(sig,rsa_pubkey_A, cipher))
		{
			send(sockfd, "ACK", 3, 0);
		}else
		{
			cout << "签名验证失败\n";
			closesocket(sockfd);
			continue;
		}

		cout << "交换密钥成功\n";
		while(true)
		{
			//接收A的加密数据
			cout << endl;
			if ((nbytes = recv(sockfd, buffer, max_buffer_len, 0)) <= 0)
			{
				cout << "与A断开连接\n";
				closesocket(sockfd);
				break;
			}
			cipher.clear();
			cipher.assign(buffer, buffer + nbytes);
			cout << "接收到来自A的" <<cipher.size()<< "字节的加密数据" << endl;
			//解密数据
			unsigned char* plain_buffer = new unsigned char[nbytes];
			memset(plain_buffer, 0, nbytes);
			aes128_decrypt((const unsigned char*)cipher.data(), cipher.size(), plain_buffer, (unsigned char*)key.data());
			string plain(plain_buffer, plain_buffer + cipher.size());
			delete[] plain_buffer;
			//验签
			if ((nbytes = recv(sockfd, buffer, max_buffer_len, 0)) <= 0)
			{
				cout << "与A断开连接\n";
				closesocket(sockfd);
				break;
			}
			sig.clear();
			sig.assign(buffer, buffer + nbytes);
			if (check_signature(sig, rsa_pubkey_A, cipher))
			{
				send(sockfd, "ACK", 3, 0);
			}
			else
			{
				cout << "签名验证失败\n";
				closesocket(sockfd);
				break;
			}
			//解除PKCS7填充
			PKCS7_unpadding(plain);
			//输出显示明文
			cout << "[解密后的数据]: " << plain << endl;
		}
	
	}
	delete[] buffer;
	getchar();
}
