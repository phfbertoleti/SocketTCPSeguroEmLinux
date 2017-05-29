/*
Rotinas de encriptacao e decriptacao (OPENSSL usando AES 256)
Autor: Pedro Bertoleti
Data: Junho/2017

Informacoes importantes:
Local de gravacao da key(32 bytes): 
Local de gravacao do iv (16 bytes):
*/

//includes
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "RotinasEncDec.h"

//defines

//prototypes locais
void handleErrors(void);

//Funcao: HandleErrors - usada quando ocorre erro na encritptacao ou decriptacao, servindo para colocar na tela o erro acusado pelo OpenSSL
//Parametros: nenhum
//Retorno: nenhum
void handleErrors(void)
{
   ERR_print_errors_fp(stderr);
   abort();
}

//Funcao: encrypt - faz a encriptacao de uma mensagem de texto (usando OpenSSL, em AES 256 CBC) 
//Parametros: 
//  - Ponteiro para mensagem de texto a ser criptografada
//  - Tamanho da mensagem de texto a ser criptografada
//  - Ponteiro para a key
//  - Ponteiro para a iv
//  - Ponteiro para a variavel que ira conter o dado criptografado / resultado da criptografia
//Retorno: tamanho do dado criptografado
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,  unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;   //objeto de context utilizado na encriptacao. Por razões de seguranca, deve ser limpo ao final do processo.
    int len;               //Guarda o tamanho da mensagem criptografada durante o processo
    int ciphertext_len;    //Contem o tamanho final da mensagem criptografada

    //Cria/inicializa contexto
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();

    /* Inicializa a operacao de encriptacao
    IMPORTANTE 
    - Como o algoritmo de criptografia usado e o AES 256 CBC, tenha certeza que
    a key e o iv tem o tamanho correto / esperado. Neste caso, significa dizer que
    a key deve ter 32 bytes (=256 bits) e o iv deve ter 16 bytes (=128 bits)

    Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();


    // Aqui, a mensagem de texto e efetivamente encriptada.
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();

    ciphertext_len = len;

    //Finalizacao da encriptacao. No processo de finalizacao de encriptacao e feito o padding.
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
        ciphertext_len += len;

    //Limpa o objeto de contexto
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


//Funcao: decrypt - faz a decriptacao de uma mensagem de texto (usando OpenSSL,$
//Parametros: 
//  - Ponteiro a mensagem criptografada
//  - Tamanho da mensagem criptografada
//  - Ponteiro para a key 
//  - Ponteiro para a iv
//  - Ponteiro para a variavel que ira conter o dado decriptografado / resultado $
//Retorno: tamanho do dado decriptografado
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;  //objeto context utilizado na decriptografia. Por razoes de seguranca, ele deve ser limpo ao final do processo
    int len;              //tamanho do dado decriptografado ao longo do processo.
    int plaintext_len;    //tamanho final do dado decriptografado

    //Cria / inicializa o context
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();

    /* Inicializa a operacao de decriptacao
    IMPORTANTE 
    - Como o algoritmo de criptografia usado e o AES 256 CBC, tenha certeza que
    a key e o iv tem o tamanho correto / esperado. Neste caso, significa dizer $
    a key deve ter 32 bytes (=256 bits) e o iv deve ter 16 bytes (=128 bits)

    Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();


    //Aqui ocorre a decriptacao de fato.
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
       handleErrors();

    plaintext_len = len;

    //Finalizacao da decriptacao.
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
       plaintext_len += len;

    //Limpa objeto de context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

