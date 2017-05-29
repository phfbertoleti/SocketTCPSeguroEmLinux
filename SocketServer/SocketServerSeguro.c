/*
Aplicacao: exemplo de troca de dados segura usando openssl e AES256.
           Lado da aplicacao: Socket Server
Autor: Pedro Bertoleti
Data: Junho/2017

Informacoes importantes:
Local de gravacao da key(32 bytes): /root/Key.txt
Local de gravacao do iv (16 bytes): /root/IV.txt
*/

//includes
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "RotinasEncDec.h" //header das rotinas de encriptacao e decriptacao

//defines
#define TAM_BUFFER_CRIPTO              1024
#define TAM_BUFFER_DECRIPTO            1024
#define TAM_BUFFER_KEY                 32   //32 bytes = 256 bits
#define TAM_BUFFER_IV                  16   //16 bytes = 128 bits
#define TAM_MAX_MENSAGEM_BOAS_VINDAS   300
#define TAM_MAX_MENSAGEM_CLIENT        2000
#define NUM_MAX_CONEXAO_CLIENTS        1
#define PORTA_SOCKET_SERVER            8888   //Nota: o valor da porta pode ser qualquer um entre 2000 e 65535. Caso der erro ao fazer o bind (ou seja, 

//Variaveis globais
char BufferKey[TAM_BUFFER_KEY];
char BufferIV[TAM_BUFFER_IV]; 
unsigned char ciphertext[TAM_BUFFER_CRIPTO];               //Buffer para o dado criptografado. Declare-o com um tamanho grande, para n$
int decryptedtext_len, ciphertext_len;


//prototypes locais
void CarregaKeyEIV(void);


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


int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c , read_size;           //socket_desc: descriptor do socket servidor 
	                                                     //client_sock: descriptor da conexao com o client
													         //read_size: contem o tamanho da estrutura que contem os dados do socket 
    struct sockaddr_in server , client;                      //server: estrutura com informações do socket (lado do servidor)
	                                                     //client: estrutura com informações do socket (lado do client) 
    char client_message[TAM_MAX_MENSAGEM_CLIENT];            //array utilizado como buffer dos bytes enviados pelo client
    char MensagemBoasvindas[TAM_MAX_MENSAGEM_BOAS_VINDAS];   //array que contem a mensagem de boas vindas (enviada no momento que a conexao e estabelecida)
    char MensagemClient[TAM_MAX_MENSAGEM_CLIENT];            //array que contem mensagem enviada ao client enquanto a conexao estiver estabelecida

    //Buffer para mensagem decriptada
    unsigned char decryptedtext[TAM_BUFFER_DECRIPTO];
    int i;

    //Inicializacoes do OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    //carrega a key e o iv salvos em local adequado
    CarregaKeyEIV();

    //Tenta criar socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        perror("Impossivel criar socket");
	return 1;
    }
    puts("Socket criado com sucesso!");

    //Prepara a estrutura de socket do servidor (contendo configurações do socket, como protocolo IPv4, porta de comunicacao e filtro de ips que podem se conectar)
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( PORTA_SOCKET_SERVER );

    //Tenta fazer Bind (informa que o referido socket operara na porta definida por PORTA_SOCKET_SERVER)
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("Erro ao fazer bind");
        return 1;
    }
    puts("Bind feito com sucesso!");

    //Faz o Listen. É permitido apenas uma conexao no socket
    listen(socket_desc , NUM_MAX_CONEXAO_CLIENTS);

    //Aguarda uma conexao
    puts("Aguardando conexao...");
    c = sizeof(struct sockaddr_in);

    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);

    //foi recebido um pedido de conexao. Verifica se o pedido foi bem sucedido
    if (client_sock < 0)
    {
 	perror("Falha ao aceitar conexao");
	return 1;
    }
    puts("Conexao aceita!");

    //Aguarda receber bytes do client
    while( (read_size = recv(client_sock , client_message, 2000, 0)) > 0 )
    {

        //Descriptografa a mensagem
	ciphertext_len = read_size;
	memcpy(ciphertext, client_message,read_size);
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, BufferKey, BufferIV,decryptedtext);

        //Mostra a mensagem recebida (decriptografada) na tela:
        printf("\n\nMensagem decriptografada: %s\n\n",decryptedtext);

        //Constroi a mensagem descriptografada a ser enviada de volta ao client
        memset(MensagemClient,0,TAM_MAX_MENSAGEM_CLIENT);
        sprintf(MensagemClient,"Voce enviou a mensagem: %s",decryptedtext);

        //Criptografa a mensagem construida e a envia ao client
        ciphertext_len = encrypt (MensagemClient, strlen ((char *)MensagemClient), BufferKey, BufferIV, ciphertext);

        write(client_sock , ciphertext , ciphertext_len);
        memset(MensagemClient,0,TAM_MAX_MENSAGEM_CLIENT);
        memset(client_message,0,TAM_MAX_MENSAGEM_CLIENT);
    }

    //client se desconectou. O programa sera encerrado.
    if(read_size == 0)
    {
        puts("Client desconectado. A aplicacao sera encerrada.");
        fflush(stdout);
        close(client_sock);   //fecha o socket utilizado, disponibilizando a porta para outras aplicacoes
    }
    else if(read_size == -1)  //caso haja falha na recepção, o programa sera encerrado
        perror("recv failed");

    return 0;
}
