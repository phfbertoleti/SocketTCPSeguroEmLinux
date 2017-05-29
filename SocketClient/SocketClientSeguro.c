/*
Aplicacao: exemplo de troca de dados segura usando openssl e AES256.
           Lado da aplicacao: Socket Client
Autor: Pedro Bertoleti
Data: Junho/2017

Informacoes importantes:
Local de gravacao da key(32 bytes): /home/root/Key.txt
Local de gravacao do iv (16 bytes): /home/root/IV.txt
*/

//Includes
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include "RotinasEncDec.h"  //header das rotinas de encriptacao e decriptacao

//defines
#define TAM_BUFFER_CRIPTO              1024
#define TAM_BUFFER_DECRIPTO            1024
#define TAM_BUFFER_KEY                 32   //32 bytes = 256 bits
#define TAM_BUFFER_IV                  16   //16 bytes = 128 bits
#define TAM_MAX_MENSAGEM_BOAS_VINDAS   300
#define TAM_MAX_MENSAGEM_CLIENT        2000 
#define NUM_MAX_CONEXAO_CLIENTS        1
#define PORTA_SOCKET_SERVER            8888

//Variaveis globais
char BufferKey[TAM_BUFFER_KEY];
char BufferIV[TAM_BUFFER_IV]; 
unsigned char ciphertext[TAM_BUFFER_CRIPTO];
int decryptedtext_len, ciphertext_len;

//prototypes locais
void CarregaKeyEIV(void);
void error(char *msg);

//Funcao: Exibe o erro de socket client na tela e finaliza o programa
//Paramentros: nenhum
//Retorno: nennhum
void error(char *msg)
{
    perror(msg);
    exit(0);
}

//Funcao: carrega Key e IV da criptografia
//Paramentros: nenhum
//Retorno: nennhum
void CarregaKeyEIV(void)
{
    FILE *arq;
    char * ptKey;
    char * ptIV;
    int ContadorBytes;

    //carrega a key (32 bytes = 256 bits)
    arq = fopen(CAMINHO_ARQUIVO_KEY, "r");
    if(arq == NULL)
        printf("Erro: impossivel carregar a KEY\n");
    else
    {
        ContadorBytes=0;
        ptKey = &BufferKey[0];
        while(ContadorBytes < TAM_BUFFER_KEY)
        {
           *ptKey = fgetc(arq);
           ptKey++;
           ContadorBytes++;
        }
    }
    fclose(arq);
    printf("[KEY] Carregada com sucesso.\n\n");

    //Carrega o IV (16 bytes = 128 bits)
    arq = fopen(CAMINHO_ARQUIVO_IV, "r");
    if(arq == NULL)
        printf("Erro: impossivel carregar o IV\n");
    else
    {
        ContadorBytes=0;
        ptIV = &BufferIV[0];
        while(ContadorBytes < TAM_BUFFER_IV)
        {
           *ptIV = fgetc(arq);
           ptIV++;
           ContadorBytes++;
        }
    }
    fclose(arq);
    printf("[IV] Carregado com sucesso.\n\n");
}

//Programa principal
int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    int i;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];
    unsigned char decryptedtext[TAM_BUFFER_DECRIPTO];
    
    //Inicializacoes do OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    //carrega a key e o iv salvos em local adequado
    CarregaKeyEIV();

    //Criacao do socket client
    portno = PORTA_SOCKET_SERVER;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) 
        error("\nERRO: impossivel abrir socket nesta porta");

    //Aqui, o socket client e criado.
    //OBS: na funcao gethostbyname(), pode ser passado como
    //parametro tanto um DNS quanto um IP.
    server = gethostbyname("COLOQUE_AQUI_IP_OU_DNS");

    //verifica se houve falha ao contactar o host
    if (server == NULL) 
    {
        fprintf(stderr,"\nERRO: o host informado nao esta ao alcance ou nao existe.\n");
        exit(0);
    }

    //inicializa com zeros a estrutura de socket
    bzero((char *) &serv_addr, sizeof(serv_addr));

    //preenche a estrutura de socket
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);

    //Tenta se conectar ao socket server
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        error("\nERRO: impossivel conectar ao host.");
    else
        printf("\nConexao ao host bem sucedida!\n\n");

     
    //le a mensagem a ser enviada.
    //OBS: aqui foi usado fgets() pois a funcao gets() possui uma falha,
    //podendo causar buffer overflow.
    printf("Mensagem a ser enviada: ");
    bzero(buffer,256);
    fgets(buffer,sizeof(buffer), stdin);

    //Criptografa a mensagem construida e a envia ao host
    ciphertext_len = encrypt (buffer, strlen ((char *)buffer), BufferKey, BufferIV, ciphertext);
    n = write(sockfd,ciphertext,ciphertext_len);

    if (n < 0) 
         error("ERRO: impossivel enviar mensagem criptografada ao host");

    bzero(buffer,256);

    //aguarda receber mensagem criptografada do host
    n = read(sockfd,ciphertext,255);
    if (n < 0) 
         error("ERRO: falha ao receber dados do host");
    
    //Descriptografa a mensagem e a exibe na tela
    ciphertext_len = n;
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, BufferKey, BufferIV,decryptedtext);

    printf("\n\n[Mensagem recebida do servidor]\n\n");

    for(i=0; i<decryptedtext_len; i++)
	printf("%c",decryptedtext[i]);

    //fim de programa
    return 0;    
}
