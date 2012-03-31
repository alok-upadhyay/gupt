/* Title	:	AlokSSH - A minimal SSH server						*/
/* Source	:	ssh_server.c 								*/	
/* Date		:	12/03/2012	   							*/
/* Author	:	Alok Upadhyay	   							*/
/* Input	:	The incoming connections from clients
			- Port 2222 for incoming control messages and file transfer(inband)	*/
/* Output	:	The server prompts, the error/warning/help messages.			*/
/* Method	:	A well planned execution of Linux function/system calls			*/
/* Possible Further Improvements :	1. User account creation/authentication -not done, since it is tftp type only
					2. A good/innovative prompt.		-done
					3. An impressive banner! :P		-done
					4. Serve users across multiple sessions -done
					5. Serve multiple users at the same time -not done	
					6. Storing logs of the commands executed -not done		
					7. How to transfer using sendfile()	-done 		*/

/* Included header files */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <openssl/sha.h>		// For SHA1() function.


/* Pre-processor directives */
#define DELIM " "
#define die(e) do { fprintf(stderr, e); exit(EXIT_FAILURE); } while (0);
#define CONTROL_PORT_NO 2222;



/* Functions and subroutines declaration */
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





/* Global data-structures */
int sock, connected, bytes_recieved , fd, true = 1, control_port, file_bytes_recieved;
char send_data[20] , recv_data[1024], response[4096], buffer[8192], file_recv_data[4096];
struct sockaddr_in server_addr, client_addr, server_addr_file, client_addr2;
int sin_size, sin_size2;
int authorized, name_present;
FILE *password_fp;
char recvd_username[100], recvd_pass_hash[1020];	


void main()
{
	createPasswordFile();
	adminMenu();	
}

void createPasswordFile()
{
	password_fp = (FILE *)fopen("passwd.lst", "w");
	fputs("Username : Password's SHA-1 Hash\n", password_fp);
}

void adminMenu()
{
	int chosen_option;	
	
	printf("\n\n		Welcome to the AlokSSH Server Admin Console		\n\n");
	printf("The server is not running, it needs your permission to power up. Also, you can do some administrative tasks like adding/deleting users before powering the server up.\n");
	printf("Please choose one of the following:\n");
	printf("1. Create Account\n");
	printf("2. Delete Account\n");
	printf("3. Power Up the server\n");
	printf("4. Shut down\n");
	
	scanf("%d", &chosen_option);
	while (getchar() != '\n');

	if(chosen_option == 1)
		addUser();
	
	if(chosen_option == 2)
		delUser();
		
	if(chosen_option == 3)
		powerUpServer();
	
	if(chosen_option == 4)
	{
		exit(0);
	}

	adminMenu();
}

void addUser()
{
	
	int chosen_option;	
	char username[20];
	unsigned char password[40], hashed_password[40];
	
	//strcpy(username, "anil kumar");	
	
	printf("\n	Welcome to the user account creation facility of the AlokSSH Server!		\n");
	printf("\nPlease enter the name of the user: ");
	gets(username);
	//while (getchar() != '\n');
		
	
	printf("Creating the new user's home folder...");
	createUserDIR(username);  
	printf("DONE!\n");	
	
	
	
	printf("Please note that the default password given to the user is the same as his username. To change press 1, to let it be like that press 2.\n");
	scanf("%d", &chosen_option);
	while (getchar() != '\n');	

	if(chosen_option == 1)
	{
		printf("Enter new password for %s: ", username);
		scanf("%s", password);
	}
	else
	{
		strcpy(password, username);
	}
		
	hash_pass(password, hashed_password);
	
	printf("Hash of the password: ");
	int i;
	for(i=0 ; i<20 ; i++)
	{
		printf("%02x", hashed_password[i]);
	}
	printf("\n");


	writeToPasswordFile(username, hashed_password);
}

void hash_pass(unsigned char *plain, unsigned char *hashed)
{
	SHA1(plain, strlen(plain), hashed);	
}


void writeToPasswordFile(char *user, unsigned char *pass)
{
	int i;
	strcat(user, " : ");
	fputs(user, password_fp);
	
	for(i=0 ; i<20 ; i++)
		fprintf(password_fp, "%02x", pass[i]);
	
	fputs("\n", password_fp);
	
}

void createUserDIR(char *username)
{
	int output;

	if (username != NULL)
	{
		int link[2];
		pid_t pid;
  		char output_of_mkdir[4096];
	
		if (pipe(link)==-1)
			die("pipe");

		if ((pid = fork()) == -1)
    			die("fork");

 		if(pid == 0) 
		{
			dup2 (link[1], STDOUT_FILENO);
			close(link[0]);
		    
			if(username != NULL)				
				execl("/bin/mkdir", "/bin/mkdir", username, (char *) 0);
			else
				printf("Enter a proper username. Error in creating user dir");
		}
		else 
		{

			    close(link[1]);	
			    read(link[0], output_of_mkdir, sizeof(output_of_mkdir));
			    //printf("Output: (%s)\n", output_of_mkdir);
			    strcpy(response, "");
			    wait(NULL);
			    
			    
		}
		
		
	}
			
}

void delUser()
{
	printf("Yet to implement delUser\n");
}

void powerUpServer()
{
	/* The actual method which powers the server up and it becomes accessible to the users */
	fputs("END", password_fp);
	fclose(password_fp);
	/* Function Calls for actual working of the server*/	
	setupServerPrimaries();
	recieveUsername();
	globalAuthManager();
}

void recieveUsername()
{
	//Accepting client connection here.
	sin_size = sizeof(struct sockaddr_in);
	connected = accept(sock, (struct sockaddr *)&client_addr,&sin_size);
	
	//Recieving the username entered by client.
	bytes_recieved = recv(connected, recvd_username, 20, 0);
	recvd_username[bytes_recieved] = '\0';
	
	//Opening the user directory to know if the user is registered.
	FILE *user_chek = fopen("passwd.lst", "r");
	
	printf("password file opened\n");
	
	name_present = 0;

	if( user_chek != NULL)
	{
		char line[70];
		while( fgets(line, sizeof(line), user_chek) != NULL )//&& !strcmp(line, "END"))
		{
			//Now we have the line in 'line', so we'll tokenize it to get the username out
			char * name = strtok(line, " : ");
			printf("Checking name_in_file= \"%s\" and name_recvd=\"%s\"\n", name, recvd_username);
			
			if(!strcmp(name, recvd_username))
			{
				name_present=1;
				break;
			}	
			
			if(!strcmp(line, "END"))
				break;
		}
	}
	else
		perror("Error opening file. \n");
	
	if(name_present == 1)
	{
		fclose(user_chek);
		char error_prompt[50];
		strcpy(error_prompt, "USER EXISTS\n");
		send(connected, error_prompt, strlen(error_prompt), 0);
		
		globalAuthManager();	
	}
		
	else if(name_present == 0 )
	{
		fclose(user_chek);
		char error_prompt[50];
		strcpy(error_prompt, "NO-EXIST\n");
		send(connected, error_prompt, strlen(error_prompt), 0);
		close(sock);
		//recieveUsername();	// The server goes into waiting-for-client state again if the username not present.
	}

	
}

void globalAuthManager()
{
	/* Manages higher level authorization tasks */

	/* Setting the authorized state to 0 initially*/	
	authorized = 1;	

	sendAuthPrompt();
	recievePassHash();
		
	if(authorized)
	{
		serveClients();
	}
	else
	{
		globalAuthManager();
	}
}


void sendAuthPrompt()
{
	char pass_prompt [100];// "Enter password for ";
	strcpy(pass_prompt, "Enter password for ");
	strcat(pass_prompt, recvd_username);
	strcat(pass_prompt, " : ");
	send(connected, pass_prompt, strlen(pass_prompt), 0);

}


void recievePassHash()
{
	//Recieving the pass_hash entered by client.
	bytes_recieved = recv(connected, recvd_pass_hash, 20, 0);
	printf("Passhash length = %d", bytes_recieved);
	recvd_pass_hash[bytes_recieved] = '\0';

	puts(recvd_pass_hash);
	FILE *checking = fopen("testing.psw", "w");
	fputs(recvd_pass_hash, checking);
	fclose(checking);
	//int i;
	//for(i=0 ; i<50 ; i++)
	//	printf("%02x", recvd_pass_hash[i]);
	//printf("\n");	
	
	//Opening the user directory to know if the user is registered.
	//FILE * user_chek = fopen("passwd.lst", "r");
	
	authorized = 1;
/*
	if( user_chek != NULL)
	{
		char line[70];
		while( fgets(line, sizeof(line), user_chek) != NULL)
		{
			//Now we have the line in 'line', so we'll tokenize it to get the username out
			char * name = strtok(line, " : ");
			char * pass_hash = strtok(NULL, " : ");
			if(!strcmp(pass_hash, recvd_pass_hash))
			{
				authorized=1;		// Very important! This is setting the authorized bit to 1.
				break;
			}	
		}
	}
	else
		perror("Error opening file. \n");
*/	
	if(authorized)
	{
		//fclose(user_chek);
		char auth[] = "authorized";
		printf("The user was authorized\n");
		send(connected, auth, strlen(auth), 0);	

	}
	else
	{
		fclose(user_chek);
		char auth[] = "not authorized";
		send(connected, auth, strlen(auth), 0);	
	}
}





void setupServerPrimaries()
{

	/*Defining the prompt*/
	char prompt[] = "alokSSH:~>";
	strcpy(send_data, prompt);
		
	control_port = CONTROL_PORT_NO;


	/*  Setting up the socket sock on port CONTROL_PORT_NO for control message transfer */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) { // TCP connection
            perror("Socket");
            exit(1);
        }

	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) {
            perror("Setsockopt");
            exit(1);
        }
        
        server_addr.sin_family = AF_INET;    //IPv4 Protocol     
        server_addr.sin_port = htons( control_port );   // Port number  
        server_addr.sin_addr.s_addr = INADDR_ANY; 
        bzero(&(server_addr.sin_zero),8); 

        if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) // bind a name 
                                                                       == -1) {
            perror("Unable to bind");
            exit(1);
        }

        if (listen(sock, 5) == -1) { // listening to a port #
            perror("Listen");
            exit(1);
        }
		
	printf("\nSSH Server powered up and for clients at %d.\n", control_port);
}

void serveClients()
{
	
	
            	
            printf("\n I have got an authorized connection from (%s , %d)",
                   inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
		
	  
	    char banner[] = "\n\n\t\t\t Welcome to Alok's SSH Server \n\nSupported commands: ls, dir, get, put, delete <filename>, mkdir <dirname>, rmdir <dirname>, cd <dirname>, bye.\n\n";
            send(connected, banner,strlen(banner), 0);


            while (1)
            {
	      strcpy(buffer, "");
		int i=0;
		while(i<8192)
		{
			buffer[i] = '\0';
			i++;
		}
	      strcat(buffer, response);
	      strcat(buffer, send_data);
	      strcpy(send_data, buffer);
	      
	      send(connected, send_data,strlen(send_data), 0);  
	      strcpy(response, "");
	      strcpy(buffer, "");	
	      strcpy(send_data, "alokSSH:~>");

	
              bytes_recieved = recv(connected, recv_data, 1024, 0);

              recv_data[bytes_recieved] = '\0';

              if (strcmp(recv_data , "bye") == 0 || strcmp(recv_data , "Q") == 0)
              {
                close(connected);
                break;
              }

              else 
              printf("\n%s" , recv_data);
	      executeCommand(recv_data);				
              fflush(stdout);
            }
              
	
	//closeSocket();
}

void executeCommand(char *command)
{
		char BYE[] = "bye";
		char GET[] = "get";
		char PUT[] = "put";
		char DIR[] = "dir";
		char LS[] = "ls";
		char DELETE[] = "delete";
		char MKDIR[] = "mkdir";
		char RMDIR[] = "rmdir";
		char CD[] = "cd";
		char HELP[] = "help";
		
		char * first_arg ,  * second_arg ;
		int i;

		
		printf("\n\n=======New Command Entered======\n");

		if(command == NULL)
		{
			printf("The client did not enter any valid command or went down unexpectedly going to waiting mode\n");
			serveClients();
		}	
	
		printf("\n Raw command=%s \n\n", command);
		first_arg = strtok(command, DELIM);
		second_arg = strtok(NULL, DELIM);
		
		if(first_arg == NULL)
		{
			printf("The client did not enter any valid command or went down unexpectedly going to waiting mode\n");
			serveClients();
		}

		printf("first %s, second %s\n", first_arg, second_arg);


		if(!strcmp(first_arg, GET))
		{
			printf("The user entered GET command\n");	
			strcpy(response, "You just entered GET command\n");	

			if(second_arg != NULL)			
			{
				transferFile(second_arg);	
				
				for(i=0 ; i<4095 ; i++)		
				{
				    
				    response[i] = '\0';
				}
		
				send(connected, response,strlen(response), 0); 

				for(i=0 ; i<4095 ; i++)		
				{
				    
				    response[i] = '\0';
				}
						

			}
			else
				strcpy(response, "Bad command for get : Usage >> get <dir_name>\n");
		}			
		
		else if(!strcmp(first_arg, PUT))
		{   
		    if(second_arg != NULL)
			{  
			printf("The user entered PUT command\n");
			file_bytes_recieved = recv(connected, file_recv_data, 4096, 0);
		        file_recv_data[file_bytes_recieved] = '\0';
			writeToFile(second_arg, file_recv_data); //second_arg=filename; file_recv_data=actual recieved data
			printf("recieved %d bytes\n", file_bytes_recieved);
			strcpy(response, "Data bytes recieved successfully at the server.\n");		
			}
		
		    else
			strcpy(response, "Bad command for put : Usage >> put <dir_name>\n");	 	
		}
		
		else if(!strcmp(first_arg, LS) || !strcmp(first_arg, DIR))
		{
			printf("The user entered LS command\n");
			int link[2];
			pid_t pid;
  			char output_of_ls[4096];

  			if (pipe(link)==-1)
    				die("pipe");

			if ((pid = fork()) == -1)
    				die("fork");

 			if(pid == 0) {

			    dup2 (link[1], STDOUT_FILENO);
			    close(link[0]);
				if(second_arg != NULL)				
				    execl("/bin/ls", "/bin/ls", "-r", second_arg, "-l", (char *) 0);
				else
					execl("/bin/ls", "/bin/ls", "-r", "-t", "-l", (char *) 0);			
				    

			} 
			else {

			    close(link[1]);
				int i;
			    for(i=0 ; i<4095 ; i++)		
				{
				    output_of_ls[i] = '\0';
				    response[i] = '\0';
				}
			    printf("The value of output_of_ls after flush: %s \n", output_of_ls);	
			    read(link[0], output_of_ls, sizeof(output_of_ls));
			    printf("Output: (%s)\n", output_of_ls);
			    strcpy(response, "");
			    strcpy(response, output_of_ls);
			    
			    wait(NULL);

			}

		}
		
		else if(!strcmp(first_arg, DELETE))
		{
			printf("The user entered DELETE command\n");
			int link[2];
			pid_t pid;
  			char output_of_delete[4];

  			if (pipe(link)==-1)
    				die("pipe");

			if ((pid = fork()) == -1)
    				die("fork");

 			if(pid == 0) {

			    dup2 (link[1], STDOUT_FILENO);
			    close(link[0]);
				if(second_arg != NULL)				
				    execl("/bin/rm", "/bin/rm", "-rf", "", second_arg, (char *) 0);
				else
					strcpy(response, "Bad command for delete : Usage >> delete <filename>\n");

			} else {

			    close(link[1]);	
			    read(link[0], output_of_delete, sizeof(output_of_delete));
			    printf("Output: (%s)\n", output_of_delete);
				strcpy(response, "");
			    strcpy(response, output_of_delete);
			    wait(NULL);

			}

		}

		else if(!strcmp(first_arg, MKDIR))
		{
			printf("The user entered MKDIR command\n");
			int link[2];
			pid_t pid;
  			char output_of_mkdir[4096];

  			if (pipe(link)==-1)
    				die("pipe");

			if ((pid = fork()) == -1)
    				die("fork");

 			if(pid == 0) {

			    dup2 (link[1], STDOUT_FILENO);
			    close(link[0]);
			    
				if(second_arg != NULL)				
				    execl("/bin/mkdir", "/bin/mkdir", second_arg, (char *) 0);
				else
					strcpy(response, "Bad command for mkdir : Usage >> mkdir <dir_name>\n");

			} else {

			    close(link[1]);	
			    read(link[0], output_of_mkdir, sizeof(output_of_mkdir));
			    printf("Output: (%s)\n", output_of_mkdir);
			    strcpy(response, "");
			    wait(NULL);

			}

		}
	
		else if(!strcmp(first_arg, RMDIR))
		{
			printf("The user entered RMDIR command\n");
			int link[2];
			pid_t pid;
  			char output_of_rmdir[4];

  			if (pipe(link)==-1)
    				die("pipe");

			if ((pid = fork()) == -1)
    				die("fork");

 			if(pid == 0) {

			    dup2 (link[1], STDOUT_FILENO);
			    close(link[0]);
			    
				if(second_arg != NULL)				
				   {
					 execl("/bin/rm", "/bin/rm", "-rf", "", second_arg, (char *) 0);
					 
				    }
				else
					strcpy(response, "Bad command for mkdir : Usage >> mkdir <dir_name>\n");
				
			} else {

			    close(link[1]);	
			    read(link[0], output_of_rmdir, sizeof(output_of_rmdir));
			    printf("Output: (%s)\n", output_of_rmdir);
			    strcpy(response, "");
			    wait(NULL);

			}

		}
		
		else if(!strcmp(first_arg, CD))
		{
			printf("The user entered CD command\n");
			int link[2];
			pid_t pid;
  			char output_of_cd[4096];

  			if (pipe(link)==-1)
    				die("pipe");

			if ((pid = fork()) == -1)
    				die("fork");

 			if(pid == 0) {

			    dup2 (link[1], STDOUT_FILENO);
			    close(link[0]);
			    
				if(second_arg != NULL)				
				   {
					int result =chdir(second_arg);
					if(result != -1)					
					{strcat(response, "PWD changed to ");
					strcat(response, second_arg);
					strcat(response, "\n");
					}
					else
					{
						perror("Couldn't execute\n");
						strcat(response, "Bad directory name\n");
					}
					 
				    }
				else
					strcpy(response, "Bad command for mkdir : Usage >> mkdir <dir_name>\n");
				
			} else {

			    close(link[1]);	
			    read(link[0], output_of_cd, sizeof(output_of_cd));
			    printf("Output: (%s)\n", output_of_cd);
			    strcpy(response, "");
			    wait(NULL);

			}

		}
		
		else if(!strcmp(first_arg, BYE))
		{		
			printf("The user entered BYE command\n");
			//free(first_arg); 
			//free(second_arg);
			printf("reaching here\n");
			//closeSocket();
			//close(connected);
			serveClients();
			//exit(0);
		}
		else if(!strcmp(first_arg, HELP))
		{
			printf("The user entered BYE command\n");
			strcpy(response, "Supported commands: ls, dir, get, put, delete <filename>, mkdir <dirname>, rmdir <dirname>, cd <dirname>, bye.\n");
		}

		else
		{
			printf("Invalid command entered\n");
			strcpy(response, "Bad command : type 'help' for more info.\n");
		}
}

void transferFile(char *filename)
{
	struct stat stat_buf;	/* argument to fstat */
	off_t offset = 0;          /* file offset */
	int rc;


	/* null terminate and strip any \r and \n from filename */
		//filename[rc] = '\0';
	 	//if (filename[strlen(filename)-1] == '\n')
		//filename[strlen(filename)-1] = '\0';
		//if (filename[strlen(filename)-1] == '\r')
		//filename[strlen(filename)-1] = '\0';



	/* open the file to be sent */
	    fd = open(filename, O_RDONLY);
	    if (fd == -1) {
	      fprintf(stderr, "unable to open '%s': %s\n", filename, strerror(errno));
	      exit(1);
	    }

	/* get the size of the file to be sent */
	    fstat(fd, &stat_buf);

    	/* copy file using sendfile */
	    offset = 0;
	    rc = sendfile (connected, fd, &offset, stat_buf.st_size);
	    if (rc == -1) {
	      fprintf(stderr, "error from sendfile: %s\n", strerror(errno));
	      exit(1);
	    }
	    if (rc != stat_buf.st_size) {
	      fprintf(stderr, "incomplete transfer from sendfile: %d of %d bytes\n",
	              rc,
	              (int)stat_buf.st_size);
	      exit(1);
	    }
	
    	/* close descriptor for file that was sent */
	    close(fd);
	
}

void writeToFile(char *filename, char *data1)
{
	FILE *fp;
	
	puts(data1);	

	fp = fopen(filename, "w");
	if (fp!=NULL)
 	 {
  		 fputs ( data1,fp);
  	 	 fclose (fp);
  	 }

}
	
void closeSocket()
{
	close(sock);
}
