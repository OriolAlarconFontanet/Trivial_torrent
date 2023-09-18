#include "file_io.h"
#include "logger.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
 


static const uint32_t MAGIC_NUMBER = 0xde1c3233; // = htonl(0x31321cde);

static const uint8_t MSG_REQUEST = 0;
static const uint8_t MSG_RESPONSE_OK = 1;
static const uint8_t MSG_RESPONSE_NA = 2;

enum { RAW_MESSAGE_SIZE = 13 };

int client_ttorrent(char** argv);
int server_ttorrent(char** argv);

/**
 * Main function.
 */
int main(int argc, char **argv) {

	set_log_level(LOG_DEBUG);
	int result = 0;
	(void)argc;

	if (argc == 2) {

		result = client_ttorrent(argv);
	}
	else if (argc == 4) {
		result = server_ttorrent(argv);
	}
	return result;

}


int client_ttorrent(char** argv) {

	//Creacio estructura torrent i block
	struct torrent_t torrent;
	struct block_t block;

	// Buscar path del arxiu
	char File[strlen(argv[1]) - 9 + 1];
	strncpy(File, argv[1], strlen(argv[1]) - 9);
	File[strlen(argv[1]) - 9] = '\0';
	
	// Creacio arxiu torrent
	if (create_torrent_from_metainfo_file(argv[1], &torrent, File) < 0) {
		perror("Error al crear el torrent file");
		return -1;
	}
	
	//Creacio del socket client
	int sock;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	uint8_t sendMessage[RAW_MESSAGE_SIZE];


	//Mirar si s'ha creat el socket
	if (sock < 0) {
		perror("Socket no creat");
		return -1;
	}
	
	//Variable dels blocks correctes
	uint64_t Blocks_correctes = 0;


	//Bucle principal per rebre dades del arxiu torrent
	for (uint64_t i = 0; i < torrent.peer_count; i++) {

		//Adreça i port del server
		struct sockaddr_in serverAddr;
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		serverAddr.sin_port = torrent.peers[i].peer_port;

		//Conexio al servidor
		connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));


		for (uint64_t block_number = 0; block_number < torrent.block_count; block_number++) {


			uint64_t nSize = get_block_size(&torrent, block_number);
			uint8_t  receiveMessage[nSize];


			//Enviar missatge
			sendMessage[0] = (uint8_t)(MAGIC_NUMBER >> 24) & 0xff;
			sendMessage[1] = (uint8_t)(MAGIC_NUMBER >> 16) & 0xff;
			sendMessage[2] = (uint8_t)(MAGIC_NUMBER >> 8) & 0xff;
			sendMessage[3] = (uint8_t)(MAGIC_NUMBER >> 0) & 0xff;
			sendMessage[4] = MSG_REQUEST;
			sendMessage[5] = (uint8_t)(block_number >> 56) & 0xff;
			sendMessage[6] = (uint8_t)(block_number >> 48) & 0xff;
			sendMessage[7] = (uint8_t)(block_number >> 40) & 0xff;
			sendMessage[8] = (uint8_t)(block_number >> 32) & 0xff;
			sendMessage[9] = (uint8_t)(block_number >> 24) & 0xff;
			sendMessage[10] = (uint8_t)(block_number >> 16) & 0xff;
			sendMessage[11] = (uint8_t)(block_number >> 8) & 0xff;
			sendMessage[12] = (uint8_t)(block_number >> 0) & 0xff;
			
			//enviar dades?
			if (send(sock, sendMessage, RAW_MESSAGE_SIZE, 0) == 0) {
				perror("No s'ha enviat res");
				return -1;

			}
			//Rebre dades?
			if (recv(sock, receiveMessage, RAW_MESSAGE_SIZE, 0) == 0) {
				perror("No s'ha rebut res");
				return -1;				
				
			}

			uint8_t Trcv = receiveMessage[4];

			if (Trcv == MSG_RESPONSE_OK) {
				recv(sock, receiveMessage, nSize, MSG_WAITALL);

				block.size = nSize;
				for (uint64_t j = 0; j < nSize; j++) {
					block.data[j] = receiveMessage[j];
				}

				int storeResult = store_block(&torrent, block_number, &block);
				if (storeResult == 0) {
					//block esta be guardat
					Blocks_correctes++;
				}
			}

			if (Trcv == MSG_RESPONSE_NA) {
				perror("No s'ha rebut res");
				return -1;
			}

		}
		//tancar socket client
		if (close(sock) > 0){
		perror("No s'ha tancat el socket del client");
		return -1;
	}

	}
	//Tancar socket client
	if (close(sock) > 0){
		perror("No s'ha tancat el socket del client");
		return -1;
	}
	//Destruir el arxiu torrent		
	if (destroy_torrent(&torrent) != 0) {
		perror("Error al destruir el arxiu torrent");
		return -1;
	}
	return 0;
	}







int server_ttorrent(char** argv) {

	//Creacio de la estructura torrent
	struct torrent_t torrent;

	//Buscar path del arxiu torrent
	char* File = (char*)malloc(strlen(argv[3]) + 1);
	strcpy(File, argv[3]);
	strtok(File, ".");
	
	//Creacio del arxiu torrent
	if (create_torrent_from_metainfo_file(argv[3], &torrent, File) < 0) {
		perror("Error creacio del arxiu");
		free(File);
		return 1;
	}
	free(File);
	
	//Creacio del socket del server
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	//Veure si s'ha creat
	if (sock < -1) {
		perror("Socket no creat");
		return -1;
	}

	//Adreça y port
	struct sockaddr_in serverAddr, client_addr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((uint16_t)atoi(argv[2]));
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

	
	if (bind(sock, (const struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
		perror("No s'ha fet bind");
		return -1;
	}



	//Escoltar si hi ha algun client conectat
	if (listen(sock, 5) < 0) {
		perror("No hi ha nignun client");
		return 1;
	}

	uint8_t reviceMessage[RAW_MESSAGE_SIZE];

	socklen_t sockclient = sizeof(client_addr);
	
	//Bucle principal per anar enviar el contingut del arxiu en diferent ports
	for (;;) {
		
		int clientSock = accept(sock, (struct sockaddr*)&client_addr, &sockclient);

		if (clientSock < 0){
			perror("No s'ha acceptat ningun client");
			return -1;
		}

		
		else if ((fork()) == 0) {
			
			close(sock);

		
			for (;;) {

				//Rebre si esta revent informacio
				if (recv(clientSock, reviceMessage, RAW_MESSAGE_SIZE, MSG_WAITALL) == -1){
					perror("No s'ha rebut res del client");
					return -1;
				}
				else {
					//Block
					uint64_t rBlock = ((uint64_t)reviceMessage[5] << 56)
						| ((uint64_t)reviceMessage[6] << 48)
						| ((uint64_t)reviceMessage[7] << 40)
						| ((uint64_t)reviceMessage[8] << 32)
						| ((uint64_t)reviceMessage[9] << 24)
						| ((uint64_t)reviceMessage[10] << 16)
						| ((uint64_t)reviceMessage[11] << 8)
						| ((uint64_t)reviceMessage[12] << 0);



					struct block_t blockS;		
					//Carregar el block
					load_block(&torrent, rBlock, &blockS);
	
					uint64_t blockSize = get_block_size(&torrent, rBlock);
					uint8_t sendMessage[RAW_MESSAGE_SIZE + blockSize];

				
					//Enviar missatge

					sendMessage[0] = (uint8_t)((MAGIC_NUMBER >> 24) & 0xff);
					sendMessage[1] = (uint8_t)((MAGIC_NUMBER >> 16) & 0xff);
					sendMessage[2] = (uint8_t)((MAGIC_NUMBER >> 8) & 0xff);
					sendMessage[3] = (uint8_t)((MAGIC_NUMBER >> 0) & 0xff);
					sendMessage[4] = MSG_RESPONSE_OK;
					sendMessage[5] = (uint8_t)((rBlock >> 56) & 0xff);
					sendMessage[6] = (uint8_t)((rBlock >> 48) & 0xff);
					sendMessage[7] = (uint8_t)((rBlock >> 40) & 0xff);
					sendMessage[8] = (uint8_t)((rBlock >> 32) & 0xff);
					sendMessage[9] = (uint8_t)((rBlock >> 24) & 0xff);
					sendMessage[10] = (uint8_t)((rBlock >> 16) & 0xff);
					sendMessage[11] = (uint8_t)((rBlock >> 8) & 0xff);
					sendMessage[12] = (uint8_t)((rBlock >> 0) & 0xff);

					//Resize
					for (uint64_t i = 0; i < blockSize; i++)
						sendMessage[RAW_MESSAGE_SIZE + i] = blockS.data[i];


					//Enviar dades al client
					if (send(clientSock, sendMessage, sizeof(sendMessage), 0) < 0){
						perror("No s'ha enviat res");
						return -1;
					}
				}

			}

			//Tancar el socket del client
			if (close(clientSock) < 0){
				perror("No s'ha tancat el socket del client");
				return -1;
			}
		}

		//Tancar el socket del client
		if (close(clientSock) < 0){
			perror("No s'ha tancat el socket del client");
			return -1;
		}
	}
	//Tancar el socket del server
	if (close(sock) < 0){
		perror("No s'ha tancat el socket del client");
		return -1;
	}
	//Destruir el arxiu torrent		
	if (destroy_torrent(&torrent) != 0) {
		perror("Error al destruir el arxiu torrent");
		return -1;
	}
	free(File);
}
