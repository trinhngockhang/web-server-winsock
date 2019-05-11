#include "stdafx.h"
#include <string.h>
#include <stdlib.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "winsock2.h"
#include <string>
#include <iostream>
#include <ctime>
#include <iostream>
#include <fstream>
#pragma comment(lib,"ws2_32.lib")

using namespace std;
DWORD WINAPI ClientThread(LPVOID);
// check username,pass when user login
bool check_pass(char username[], char password[]);
//check cookie exist in token list,return true if logined
bool checkUserExist(char cookie[]);
char *connection_info(struct sockaddr_in &client);
// generate token and save to tokenList
void generateToken(char *token);
//delete token
void removeToken(char cookie[]);
bool signUp(const char *buffer);
bool signUpCheck(char[], char[]);
void createNewAccount(char username[], char password[], char name[]);
SOCKET clients[64];
char *ids[64];
int numClients;
char tokenList[64][11];
int main()
{
	numClients = 0;
	
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
	SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	SOCKADDR_IN addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9000);

	bind(listener, (SOCKADDR *)&addr, sizeof(addr));
	listen(listener, 5);

	while (true)
	{
		struct sockaddr_in client_info = { 0 };
		int size = sizeof(client_info);
		SOCKET client = accept(listener, (sockaddr*)&client_info, &size);
		printf("Accepted client: %d\n", client);
		char *ipClient = connection_info(client_info);
		printf("Client IP: %s \n", ipClient);
		CreateThread(0, 0, ClientThread, &client, 0, 0);
	}

	return 0;
}

DWORD WINAPI ClientThread(LPVOID lpParam)
{
	SOCKET client = *(SOCKET *)lpParam;

	char buf[1024];
	char sendBuf[256];
	int ret;
	char cmd[64];
	char id[64];
	char tmp[64];

	char targetId[64];

	const char *errorMsg = "Loi cu phap. Hay nhap lai\n";
	
	while (true)
	{
		ret = recv(client, buf, sizeof(buf), 0);
		bool exist;
		if (ret <= 0) break;
		buf[ret] = 0;
		printf("Received: %s\n", buf);
		// get cookie
		char cookie[11] = "";
		char *restBody = strstr(buf, "Token=");
		if (restBody) {
			printf("%s", restBody);
			strncat(cookie, restBody + 6, 10);
			printf("cookie la: %s", cookie);
			exist = checkUserExist(cookie);
			printf("%d", exist);
		}
		else {
			exist = false;
		}
		
		if (strncmp(buf, "GET / HTTP", 10) == 0) {
			printf("da nhan request\n");
			//chua dang nhap
			if (!exist) {
				FILE *f = fopen("Login.html", "rb");
				while (true)
				{
					ret = fread(buf, 1, sizeof(buf), f);
					if (ret > 0)
						send(client, buf, ret, 0);
					else
						break;
				}
				fclose(f);
			}
			else {
				FILE *f = fopen("home.html", "rb");
				while (true)
				{
					ret = fread(buf, 1, sizeof(buf), f);
					if (ret > 0)
						send(client, buf, ret, 0);
					else
						break;
				}
				fclose(f);
			}
			closesocket(client);
		}
		else if (strncmp(buf, "POST /log-in", 12) == 0) {
			printf("da nhan request POST\n");
			printf("%s", buf);
			char *body = strstr(buf, "username=");
			char msg[2048] = "";
			printf("\nbody: %s", body);
			char re_username[128], *username;
			char re_password[128], *password, end[128];
			sscanf(body, "%128[^&] & %128[^&] & %s", re_username, re_password, end);
			username = re_username + 9;
			password = re_password + 9;
			printf("\n user nhap: %s pass nhap: %s\n", username, password);
			bool a = check_pass(username, password);
			if (a) {
				srand(time(NULL));
				char *header = "HTTP/1.1 200 OK\r\n Set-Cookie: Token=";
				char *end = "\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Ban da dang nhap thanh cong</h1></br><p>An vao day de tro ve trang chu</p><a href='/'><button>Go</button></a></body></html>";
				strcat(msg, header);
				char token[11];
				generateToken(token);
				strcat(msg, token);
				strcat(msg, end);
			}
			else {
				strcat(msg,"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Dang nhap khong thanh cong</h1></br><p>An vao day de dang nhap lai</p><a href='/'><button>Go</button></a></body></html>");
			}

			send(client, msg, strlen(msg), 0);
			closesocket(client);
		}
		else if (strncmp(buf, "GET /sign-up", 12) == 0) {
			FILE *f = fopen("sign-up.html", "rb");
			while (true)
			{
				ret = fread(buf, 1, sizeof(buf), f);
				if (ret > 0)
					send(client, buf, ret, 0);
				else
					break;
			}
			closesocket(client);
			fclose(f);
		}
		else if (strncmp(buf, "POST /sign-up", 13) == 0) {
			// lay du lieu o day roi ghi vao file data.txt,nho check user da ton tai hay cgya
			if (signUp(buf) == true) {
				const char *msg = "HTTP/1.1 200 OK\r\n Set-Cookie: ah=b\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Dang ki thanh cong ,an vao day dang nhap lai </br> <a href='/'><button>Go</button></a></h1> <a href='/'><button>Back</button></a> </body></html>";
				send(client, msg, strlen(msg), 0);
			}
			else {
				const char *msg = "HTTP/1.1 200 OK\r\n Set-Cookie: ahi=ahi\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Dang ki that bai,tai khoan da ton tai </h1> <a href='/'><button>Back</button></a> </body></html>";
				send(client, msg, strlen(msg), 0);
			}
			closesocket(client);
		}
		else if (strncmp(buf, "POST /command", 13) == 0) {
			char fileBuf[256];
			char *command = strstr(buf, "command=");
			char realCommand[256] = "";
			
			size_t bigsize = sizeof(command);
			int size = static_cast<int>(bigsize);
			size = size * 4;
			printf("do dai: %d", size);
			strncat(realCommand, command + 8, size) ;
			realCommand[size - 8] = 0;
			strcat(realCommand, " > c:\\test_server\\out.txt");
			printf("command: %s", realCommand);
			system(realCommand);
			FILE *f = fopen("C:\\test_server\\out.txt", "r");
			char msg[20148] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Ket qua:</h1> ";
			while (fgets(fileBuf, sizeof(fileBuf), f))
			{
				strcat(msg, "<div>");
				strcat(msg, fileBuf);
				strcat(msg, "</div>");
				printf("file: %s", fileBuf);
			}
			
			strcat(msg, "<a href='/'><button>Back</button></a> </body></html>");
			send(client, msg, strlen(msg), 0);
			fclose(f);
			closesocket(client);
		}
		else if (strncmp(buf, "GET /log-out", 12) == 0) {
			const char *msg = "HTTP/1.1 200 OK\r\n Set-Cookie: Token=aaaa\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Dang xuat thanh cong </h1> <a href='/'><button>Back</button></a> </body></html>";
			send(client, msg, strlen(msg), 0);
			removeToken(cookie);
			closesocket(client);
		}
	}
	closesocket(client);
}
char *connection_info(struct sockaddr_in &client)
{
	char *connected_ip = inet_ntoa(client.sin_addr);
	int port = ntohs(client.sin_port);
	return connected_ip;
}

bool check_pass(char username[], char password[]) {
	FILE *f = fopen("data.txt", "rb");
	int ret;
	char buf[1024];
	char userDb[128], passDb[128], end[128];
	int i = 0;
	int count = 0;
	while (true)
	{
		ret = fread(buf, 1, sizeof(buf), f);
		buf[ret] = 0;
		if (ret > 0) {
			printf("buf: %s", buf);
			for (int i = 0; i < ret + 2; i++) {
				char *lineInText;
				if (buf[i] == '\n' || i == ret + 1) {
					lineInText = buf + count;
					lineInText[i - count - 1] = 0;
					if (i == ret + 1) {
						lineInText = buf + count;
					}
					count = i + 1;
					int slpit;
					slpit = sscanf(lineInText, "%s %s %s", userDb, passDb, end);
					printf("\n user: %s pass: %s", userDb, passDb);

					if (strcmp(username, userDb) == 0 && strcmp(password, passDb) == 0) {
						printf("dung mat khau");
						return true;
					}
				}
			}
		}
		else
			break;
	}
	fclose(f);
	return false;
}

void generateToken(char *token) {
	int i = 0;
	while (i < 10) {
		
		int number = 65 + rand() % 26;
		token[i] = number;
		printf("%d\n", number);
		i++;
	}
	token[10] = 0;
	strcat(tokenList[numClients++], token);
}

bool checkUserExist(char cookie[]) {
	for (int i = 0; i < numClients; i++) {
		printf("token List: %s", tokenList[i]);
		if (strcmp(cookie, tokenList[i]) == 0) {
			return true;
		}
	}
	return false;
}

void removeToken(char cookie[]) {
	for (int i = 0; i < numClients; i++) {
		printf("token List: %s", tokenList[i]);
		if (strcmp(cookie, tokenList[i]) == 0) {
			strcat(tokenList[i], tokenList[numClients]);
			numClients--;
		}
	}
}



bool signUp(const char *buffer) {
	char *body = strstr((char*)buffer, "username=");
	char username[64];
	char password[64];
	char name[32];
	const char *msg;
	printf("body:\n\t%s\n", body);
	sscanf(body, "%*[^=] = %[^\r] \r %*[^=] = %[^\r] \r %*[^=] = %32[^\r]", username, password, name);
	printf("username: %s\n", username);
	printf("password: %s\n", password);
	printf("name: %s\n", name);
	if (signUpCheck(username, password) == TRUE) {
		createNewAccount(username, password, name);
		return true;
	}
	else {
		return false;
	}
}



bool signUpCheck(char username[], char password[]) {
	//Kiem tra xem ten da co trong file text chua
	fstream data;
	string line;
	data.open("data.txt", ios::in);
	if (data.is_open()) {
		while (getline(data, line)) {
			string usernameData = line.substr(0, line.find(" "));
			if (strcmp(username, usernameData.c_str()) == 0) {
				//dang ky that bai
				printf("Tai khoan da ton tai trong he thong!\n");
				return FALSE;
			}
		}
	}
	data.close();
	return TRUE;
}



void createNewAccount(char username[], char password[], char name[]) {
	fstream data;
	data.open("data.txt", ios::out | ios::app);
	if (data.is_open()) {
		data << username << " " << password << " " << name << "\n";
	}
	data.close();
}