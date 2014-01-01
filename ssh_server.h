#ifndef SSH_SERVER
#define SSH_SERVER

void setupServerPrimaries();
void serveClients();
void closeSocket();
void executeCommand(char *);
void transferFile(char *);
void writeToFile(char *, char *);
void createPasswordFile();
void adminMenu();
void addUser();
void delUser();
void hash_pass(unsigned char *, unsigned char *);
void writeToPasswordFile(char *, unsigned char *);
void createUserDIR(char *);
void powerUpServer();
void recieveUsername();
void globalAuthManager();
void sendAuthPrompt();
void recievePassHash();

#endif
