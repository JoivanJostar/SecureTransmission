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
bool check_signature(string sig,RSA * rsa_pubkey,string cipher)
{
	//��A�Ĺ�Կ���� ��ȡǩ����SHA256ֵ 
	string src= rsa_pub_decrypt((const unsigned char *)sig.data(),sig.size(), rsa_pubkey);
	//���ؼ���һ�����ĵ�SHA256
	string expected = sha256(cipher);
	return src == expected;
}
int main()
{
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
	RSA* rsa_prikey_B = nullptr;
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
	//��ȡB��RSA˽Կ
	if ((rsa_prikey_B = getPrikey("./RSAkey/Bprikey.pem")) == nullptr)
	{
		cout << "��ȡB��˽Կʧ��\n";
		return 0;
	}

	//�󶨲������˿ڣ��ȴ�A����
	unsigned short port = 54321; //B�Ķ˿ں�
	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//host ip addr

	int listensock = socket(AF_INET, SOCK_STREAM, 0);
	if (listensock == -1) {
		printf("����Socketʧ��\n");
		exit(0);
	}
	char on = 1;
	//����SocketΪReuse���õ�ַģʽ������������������ʱ���ٰ󶨳ɹ�
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	//�󶨶˿�
	if (::bind(listensock, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
		printf("�󶨶˿�ʧ�ܣ�����˿�%d�Ƿ�ռ���Լ��Ƿ���ڷ���ǽ���\n",port);
		exit(0);
	}
	//����
	if (listen(listensock, 10) < 0) {
		printf("�����˿�ʧ��\n");
		exit(0);
	}
	cout << "����B���ڼ�����ַ 127.0.0.1:" << port << endl;
	struct sockaddr_in clientaddr;
	::memset(&clientaddr, 0, sizeof(clientaddr));
	int addrlen = sizeof(clientaddr);
	int max_buffer_len = 1024 * 1024;
	int nbytes = 0;
	char* buffer = new char[max_buffer_len];
	memset(buffer, 0, max_buffer_len);
	for (;;) {
		cout << "�ȴ�A������......\n";
		//�������� 3������
		int sockfd = accept(listensock, (struct sockaddr*)&clientaddr, &addrlen);
		cout << "���յ�����A��TCP����" << endl;
		//������Կ
		if((nbytes=recv(sockfd,buffer,max_buffer_len,0))<=0)
		{
			cout << "��A�Ͽ�����\n";
			closesocket(sockfd);
			continue;
		}
		string cipher(buffer, buffer + nbytes);
		string key = rsa_pri_decrypt((const unsigned char *)cipher.data(), cipher.size(), rsa_prikey_B);
		//��ǩ
		if ((nbytes = recv(sockfd, buffer, max_buffer_len, 0)) <= 0)
		{
			cout << "��A�Ͽ�����\n";
			closesocket(sockfd);
			continue;
		}
		string sig(buffer, buffer + nbytes);
		if(check_signature(sig,rsa_pubkey_A, cipher))
		{
			send(sockfd, "ACK", 3, 0);
		}else
		{
			cout << "ǩ����֤ʧ��\n";
			closesocket(sockfd);
			continue;
		}

		cout << "������Կ�ɹ�\n";
		while(true)
		{
			//����A�ļ�������
			cout << endl;
			if ((nbytes = recv(sockfd, buffer, max_buffer_len, 0)) <= 0)
			{
				cout << "��A�Ͽ�����\n";
				closesocket(sockfd);
				break;
			}
			cipher.clear();
			cipher.assign(buffer, buffer + nbytes);
			cout << "���յ�����A��" <<cipher.size()<< "�ֽڵļ�������" << endl;
			//��������
			unsigned char* plain_buffer = new unsigned char[nbytes];
			memset(plain_buffer, 0, nbytes);
			aes128_decrypt((const unsigned char*)cipher.data(), cipher.size(), plain_buffer, (unsigned char*)key.data());
			string plain(plain_buffer, plain_buffer + cipher.size());
			delete[] plain_buffer;
			//��ǩ
			if ((nbytes = recv(sockfd, buffer, max_buffer_len, 0)) <= 0)
			{
				cout << "��A�Ͽ�����\n";
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
				cout << "ǩ����֤ʧ��\n";
				closesocket(sockfd);
				break;
			}
			//���PKCS7���
			PKCS7_unpadding(plain);
			//�����ʾ����
			cout << "[���ܺ������]: " << plain << endl;
		}
	
	}
	delete[] buffer;
	getchar();
}
