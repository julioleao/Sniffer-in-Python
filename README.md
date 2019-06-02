# Sniffer em Python 3

Trata-se de um trabalho realizado pelos alunos da UTFPR de Cornélio Procópio apenas para fins educacionais. Tomando como fonte o trabalho realizado pelo usuário [Bucky Roberts](https://github.com/buckyroberts), nossa proposta é a de desenvolver um analisador de pacotes (Sniffer de rede) capaz de capturar os pacotes que trafegam na rede, assim como IP de origem e destino, MAC, entre outros, utilizando a linguagem Python.

## Preparação

Nosso ambiente de trabalho foi constituído por: 

* Linux Mint 19.1 Cennamon 64 bits
* 6 GB de Ram
* SSD 240 GB
* Processador i3 de 2ª geração

Os softwares utilizados foram:

* Geany (IDE)
* Python versão 3.6.7

## Desenvolvimento

Tomando como base o formato padrão dos protocolos de rede, e com a utilização de bibliotecas como *socket* e *struct*, conseguimos realizar a coleta e analise de pacotes dos protocolos da camada de rede **IPv4**, **ICMP** e da camada de transporte **TCP** e **UDP**. Todos dados trafegados na rede serão analisados, sem exceção, através do parâmetros **65536** em *recvfrom()*, o que informa que todas as portas são válidas para análise. Optamos também por um sistema de filtradgem simples, onde o usuário vai poder escolher qual pacote ele deseja capurar através de um menu.

Começamos então definindo uma conexão, com:

```
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
```
Logo em seguida criado um laço de repetição onde todo o processo de análise será realizado, um loop infinito, dentro desse laço será testada o [ID de protocolo](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml), 1 é ICMP, 6 TCP e 17 UDP.

O algoritmo consiste em desempacotar os pacotes passando-os para uma *struct*, e em seguida "traduzí-los" para que finalmente pudesse ser mostrado ao usuário via terminal.

Por exemplo a linha 45:

```
dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
```
Onde "6s 6s H" equivale ao **MAC Header**, conforme a imagem abaixo, sendo 6 bytes para o MAC de destino, 6 bytes para o MAC de origem e 2 bytes para tipo de protocolo, totalizando assim 14 bytes de dados (data[:14]) 


![alt text](https://upload.wikimedia.org/wikipedia/commons/thumb/1/13/Ethernet_Type_II_Frame_format.svg/1024px-Ethernet_Type_II_Frame_format.svg.png?1558873821724)

O mesmo conceito se leva aos demais protocolos, como é o caso da função em desempacotar um pacote TCP.

Por exemplo a linha 72:blob:https://pasteboard.co/403dc502-efdb-4e60-bd9b-79492b0bd6be

```
(src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
```
Onde "H H L L H", equivale a *Source port*, *Destination port*, *Sequence number*, *Acknowledgement number* e por fim *Offset*, *Reserved* e *Flags* gerando dados de 14 bytes (data[:14])

![alt text](https://www.computerhope.com/jargon/p/packet.jpg)

Se vocês está se perguntando "Mas o que diabos são essas letras como parâmetro da função *struct.unpack*?". Pois bem, essa é a forma de interpretar os tipos extraídos do pacote, as letras e seus tipos associados seguem conforme a tabela abaixo:

![alt text](http://quark.sourceforge.net/infobase/pics/intro.modeleditor.importexport.struct2.png)

## Execução

Por fim, a execução do código se dá através da função principal (main()), onde serão mostrados todos os valores, antes compactados, agora descompactados e devidamente formatados para a visualização do usuário. Conforme mencionado anteriormente, nesse trabalho foram implementados a analise apenas em pacotes TCP, IPv4, ICMP e UDP, sendo assim o mesmo deve ser utilizado apenas como forma de aprendizado e não como uma aplicação comercial, para isso existem outras soluções como o tão conhecido Wireshark. 

Para a execução do programa é necessário:

* Estar em um ambiente **Linux**
* Abra o terminal [ctrl + alt + t]
* Navegue até a pasta onde se encontra o aquivo *"sniffer.py"* e execute:

```
sudo python3 sniffer.py
```

* Agora abra o navegador, navegue em alguma página e você verá os pacotes sendo analisados.

![alt text](https://i.imgur.com/9KIYQwE.png)


