# Socket TCP Seguro (em C no Linux)

Socket TCP Seguro (Linux)  Aqui é feita uma comunicação via Socket TCP em C (no Linux) de modo seguro, utilizando OpenSSL (algoritmo de encriptação / decriptação AES256 CBC). tal projeto foi explicado com detalhes em https://www.embarcados.com.br/intel-edison-comunicacao-segura-openssl/

Instruções para compilar e utilizar o projeto:

a) No sistema Linux destinado a ser socket server:

1. Neste sistema, utilize somente o conteúdo da pasta "SocketServer"
2. Uma vez com esta pasta no seu sistema, entre nela e execute o comando make para compilar.
3. Feita a compilação, basta executar o programa. Para isso, utilize o comando ./SocketServerSeguro

b) No sistema Linux destinado a ser socket client:

1. Neste sistema, utilize somente o conteúdo da pasta "SocketClient"
2. Uma vez com esta pasta no seu sistema, entre nela e execute o comando make para compilar.
3. Antes de prosseguir, tenha certeza que o programa com o socket server está executando e o socket server está em listening.
4. Execute o programa. Para isso, utilize o comando ./SocketClientSeguro
