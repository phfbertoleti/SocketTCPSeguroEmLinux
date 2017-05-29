/*
Header das rotinas de encriptacao e decriptacao. 
Autor: Pedro Bertoleti
Data: Junho/2017
*/

//defines 
//IMPORTANTE: os arquivos devem estar em local seguro, o que significa dizer que devem estar em pastas somente acessiveis pelo root
#define CAMINHO_ARQUIVO_KEY  "/root/key.txt"  //contem o caminho para o arquivo que contem a key (32 bytes)
#define CAMINHO_ARQUIVO_IV   "/root/iv.txt"  //contem o caminho para o arquivo que contem o iv (16 bytes)


//prototypes globais
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext);
