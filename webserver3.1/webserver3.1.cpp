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
//save command of user
void saveCommandUser(char username[], char *ip, char command[]);
bool signUp(const char *buffer);
bool signUpCheck(char[], char[]);
void createNewAccount(char username[], char password[], char name[]);
bool updateInformation(const char *buffer,char realUser[]);
bool checkOldPassword(const char *pOldPassword);
void changeValue(const char *pUsername, const char* type, const char *pValue);
void changeFileName();
char *getName(char *username);
SOCKET clients[64];
char *ids[64];
int numClients;
char tokenList[64][10];

const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
	return buf;
}

struct ClientThreadInfo
{
	char *ipAddress;
	SOCKET client;
};

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
		struct ClientThreadInfo clientThread;
		struct sockaddr_in client_info = { 0 };
		int size = sizeof(client_info);
		SOCKET client = accept(listener, (sockaddr*)&client_info, &size);
		printf("Accepted client: %d\n", client);
		char *ipClient = connection_info(client_info);
		printf("Client IP: %s \n", ipClient);
		clientThread.client = client;
		clientThread.ipAddress = ipClient;
		CreateThread(0, 0, ClientThread, &clientThread, 0, 0);
	}

	return 0;
}

DWORD WINAPI ClientThread(LPVOID lpParam)
{
	struct ClientThreadInfo clientStruct = *(ClientThreadInfo* )lpParam;
	SOCKET client = clientStruct.client;
	char *ipAddress = clientStruct.ipAddress;
	char buf[1024 * 8];
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
		// get cookie,that ra day la lay token trong cookie thoi k phai lay ca cookie,luoi sua
		char cookie[11] = "";
		char *restBody = strstr(buf, "Token=");
		char *userCookie = strstr(buf, "userlogined=");
		char userIncludeDownLine[64];
		// day la thang user dang dang nhap realUser
		char realUser[32];
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
		if (userCookie) {
			sscanf(userCookie, "%*[^=] = %[^\r]", realUser);
			//realUser[sizeof(realUser) - 2] = 0;
			printf("day la doan can tach: %s", realUser);
		}
		
		if (strncmp(buf, "GET / HTTP", 10) == 0) {
			const char  *yo = "HTTP/1.1 200 OK\r\n Content-Type: text/html\r\n\r\n";
			send(client, yo, strlen(yo), 0);
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
				//send phan dau cua trang home
				FILE *f = fopen("headerHome.txt", "rb");
				while (true)
				{
					ret = fread(buf, 1, sizeof(buf), f);
					if (ret > 0)
						send(client, buf, ret, 0);
					else
						break;
				}
				fclose(f);
				// ghep ten user
				printf("user name la: %s", realUser);
				char *name = realUser;
				char *nameUserinDb = getName(name);
				send(client, nameUserinDb, strlen(nameUserinDb) + 1, 0);
				FILE *fEnd = fopen("endHome.txt", "rb");
				while (true)
				{
					ret = fread(buf, 1, sizeof(buf), fEnd);
					if (ret > 0)
						send(client, buf, ret, 0);
					else
						break;
				}
				fclose(fEnd);
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
				char *end = "\r\nContent-Type: text/html\r\n\r\n";
				strcat(msg, header);
				char token[11];
				generateToken(token);
				strcat(msg, token);
				strcat(msg, "  ");
				strcat(msg, "userlogined=");
				strcat(msg, username);
				strcat(msg, end);
				send(client, msg, strlen(msg), 0);
				FILE *f = fopen("loginSuccess.html", "rb");
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
				const char  *yo = "HTTP/1.1 200 OK\r\n Content-Type: text/html\r\n\r\n";
				send(client, yo, strlen(yo), 0);
				FILE *f = fopen("loginFail.html", "rb");
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
		else if (strncmp(buf, "GET /sign-up", 12) == 0) {
			const char  *yo = "HTTP/1.1 200 OK\r\n Content-Type: text/html\r\n\r\n";
			send(client, yo, strlen(yo), 0);
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
		else if (strncmp(buf, "POST /sign-up", 13) == 0 ) {
			// lay du lieu o day roi ghi vao file data.txt,nho check user da ton tai hay cgya
			if (signUp(buf) == true) {
				const char *msg = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Dang ki thanh cong ,an vao day dang nhap lai </br> <a href='/'><button>Go</button></a></h1> <a href='/'><button>Back</button></a> </body></html>";
				send(client, msg, strlen(msg), 0);
			}
			else {
				const char *msg = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Dang ki that bai,tai khoan da ton tai </h1> <a href='/'><button>Back</button></a> </body></html>";
				send(client, msg, strlen(msg), 0);
			}
			closesocket(client);
		}
		else if (strncmp(buf, "POST /command", 13) == 0) {
			char fileBuf[256];
			char *command = strstr(buf, "command=");
			int size = strlen(command);
			printf("size: %d", size);
			char realCommand[256] = "";
			strncat(realCommand, command + 8, size - 10) ;
			realCommand[size - 8] = 0;
			saveCommandUser(realUser, realCommand, ipAddress);
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
			if (!fileBuf) strcat(msg, "<p> Noi dung cau lenh khong hop le </p>");
			strcat(msg, "<a href='/'><button>Back</button></a> </body></html>");
			send(client, msg, strlen(msg), 0);
			fclose(f);
			closesocket(client);
		}
		else if (strncmp(buf, "GET /log-out", 12) == 0) {
			const char *msg = "HTTP/1.1 200 OK\r\n Set-Cookie: Token=aaaa\r\nContent-Type: text/html\r\n\r\n";
			send(client, msg, strlen(msg), 0);
			FILE *f = fopen("logoutSuccess.html", "rb");
			while (true)
			{
				ret = fread(buf, 1, sizeof(buf), f);
				if (ret > 0)
					send(client, buf, ret, 0);
				else
					break;
			}
			fclose(f);
			removeToken(cookie);
			closesocket(client);
		}
		else if (strncmp(buf, "GET /update", 11) == 0 && exist) {
			const char  *yo = "HTTP/1.1 200 OK\r\n Content-Type: text/html\r\n\r\n";
			send(client, yo, strlen(yo), 0);
			FILE *f = fopen("UpdateInfomation.html", "rb");
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
		else if (strncmp(buf, "POST /update", 11) == 0) {
			if (updateInformation(buf, realUser) == true) {
				const char *msg = "HTTP/1.1 200 OK\r\n Content-Type: text/html\r\n\r\n<html><body><h1>Cap nhat thanh cong </h1> <a href='/'><button>Back</button></a> </body></html>";
				send(client, msg, strlen(msg), 0);
			}
			else
			{
				const char *msg = "HTTP/1.1 200 OK\r\n Content-Type: text/html\r\n\r\n<html><body><h1>Loi</h1> <a href='/update'><button>Back</button></a> </body></html>";
				send(client, msg, strlen(msg), 0);
			}
			closesocket(client);
		}
		else {
			printf("da vao dy");
			char *msg = "HTTP/1.1 200 OK\r\n Content-Type: text/html\r\n\r\n<html><body><h1>Request Invalid</h1> <a href='/'><button>Back</button></a> </body></html>";
			send(client, msg, strlen(msg), 0);
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
	char buf[1024 * 8];
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
						fclose(f);
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
	for (int i = 0; i <= numClients; i++) {
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
				data.close();
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

void saveCommandUser(char username[], char *ip, char command[]) {
	fstream data;
	data.open("commandlog.txt", ios::out | ios::app);
	if (data.is_open()) {
		data << username << "&" << ip << "&" << command << "&" << currentDateTime() << "\n";
	}
	data.close();
}

bool updateInformation(const char *buffer, char username[]) {
	char *body = strstr((char*)buffer, "oldPassword=");
	char oldPassword[64] = "\0";
	char newPassword[64] = "\0";
	char newName[32] = "\0";
	char *usernamePointer = username;
	printf("realname duoc truyen vao o updateinfor la: %s \n", username);
	sscanf(body, "oldPassword=%[^\r] \r\nnewPassword=%[^\r] \r\nnewName=%[^\r] \r\n", oldPassword, newPassword, newName);
	if (checkOldPassword(oldPassword) == true) {
		if (strlen(newPassword) > 0) {
			changeValue(usernamePointer, "password", newPassword);
		}
		if (strlen(newName) > 0) {
			printf("new name 1 : %s", newName);
			changeValue(usernamePointer, "name", newName);
		}
	}
	else return false;
	return true;
}

bool checkOldPassword(const char *pOldPassword) {
	char userDb[64], passDb[64], name[64];
	fstream data;
	string line;
	data.open("data.txt", ios::in);
	if (data.is_open()) {
		while (getline(data, line)) {
			sscanf(line.c_str(), "%s %s %[^\n]", userDb, passDb, name);
			cout << "usename: " << userDb << " pass: " << passDb << " name: " << name << endl;
			if (strcmp(pOldPassword, passDb) == 0) {
				data.close();
				return true;
			}
		}
	}
	data.close();
	return false;
}

char *getName(char *username) {
	fstream data;
	string line;
	data.open("data.txt", ios::in);
	printf("user name truyen getname: %s", username);
	char userDb[64], passDb[64], name[64];
	if (data.is_open()) {
		while (getline(data, line)) {
			sscanf(line.c_str(), "%s %s %[^\n]", userDb, passDb, name);
			printf("user DB getname: %s", userDb);
			if (strcmp(username, userDb) == 0) {
				data.close();
				return name;
			}
		}
	}
	data.close();
	return "user";
}

void changeValue(const char *pUsername, const char* type, const char *pValue) {
	fstream data;
	fstream newFile;
	string line;
	char userDb[64], passDb[64], name[64];
	data.open("data.txt", ios::in);
	newFile.open("temp.txt", ios::out);
	if (data.is_open()) {
		while (getline(data, line)) {
			sscanf(line.c_str(), "%s %s %[^\n]", userDb, passDb, name);
			if (strcmp(pUsername, userDb) == 0) {
				printf("dung pass roi: %s", pValue);
				if (strcmp(type, "password") == 0) {
					// Sua password
					newFile << userDb << " " << pValue << " " << name << "\n";
				}
				else if (strcmp(type, "name") == 0) {
					printf("name: %s", pValue);
					//Sua nick name
					newFile << userDb << " " << passDb << " " << pValue << "\n";
				}
			}
			else {
				newFile << line << "\n";
			}
		}
	}
	data.close();
	newFile.close();
	changeFileName();
	//xoa het thong tin di
	newFile.open("temp.txt", ios::out);
	newFile.close();
}
void changeFileName() {
	int res = 0;
	res = remove("data.txt");
	res = rename("temp.txt", "data.txt");
}