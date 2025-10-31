# Introdução e Contexto Geral

O objetivo deste texto será a apresentação dos conhecimentos adquiridos no primeiro desafio de projeto do Bootcamp Santander 2025 de Cibersegurança. O desafio trata-se da utilização da ferramenta Medusa para realização de uma Ataque de Força Bruta. 

A intenção é trazer os conceitos por de trás das ferramentas utilizadas como forma de sistematizar os conhecimentos adquiridos. Ressalto que, por não ser oriundo da área de Ciência da Computação, buscarei trazer exemplos práticos nas explicações dos conceitos.

O objetivo deste trabalho é percorrer o fluxo de ações a serem empregadas para a realização deste ataque. Para isso, utilizarei as seguintes ferramentas:

* [Kali Linux](https://www.kali.org/docs/introduction/what-is-kali-linux/#:~:text=Kali%20Linux%20(formerly,professionals%20and%20hobbyists.)): distribuição do Linux baseada no Debian específica para a realização de testes de invação e auditorias de segurança. O Kali já vem com diversas ferramentas instaladas, inclusive, o Medusa; 
* [Metasploitable2](https://sourceforge.net/projects/metasploitable/#:~:text=Metasploitable%20is%20an%20intentionally%20vulnerable%20Linux%20virtual%20machine.%20This%20VM%20can%20be%20used%20to%20conduct%20security%20training%2C%20test%20security%20tools%2C%20and%20practice%20common%20penetration%20testing%20techniques.): máquina virtual Linux intencionalmente vulnerável utilizada para a treinamento, testes de ferramentas de segurança e práticas de *pentest*;
* [nmap](https://nmap.org/man/pt_BR/): ferramenta de código aberto usada para exploração de redes e auditoria de segurança. Ela pode determinar os *hosts* disponíveis na rede, quais serviços estes *hosts* disponibilizam, os sistemas operacionais executados pelos *hosts*, dentre outros;
* [DVWA](https://github.com/digininja/DVWA) (*Damn Vulnerable Web Application*): aplicação *web* baseada em PHP e MariaDB intencionalmente vulnerável com a finalidade de treinamento;
* [protocolos FTP](https://datatracker.ietf.org/doc/rfc959/#:~:text=The%20objectives%20of,use%20by%20programs.): protocolo de rede cujo principal objetico é regulamentar a transferência de arquivos entre sistemas.

## Protocolo de Autenticação

Protocolo de autenticação é o processo que as aplicações *web* utilizam para confirmar que certo usuário poderá acessar ao conteúdo daquela aplicação *web*. Do ponto de vista do usuário, estes processos de autenticação são mais visíveis quando ele está tentando acessar um serviço por meio de suas credenciais (usuário e senha).

### Autenticação *Stateless*

Na autenticação *stateless*, após o usuário fazer seu acesso ao sistema, este recebe um *token* que contém todas as informações necessárias para validar o acesso do usuário em requisições futuras. Nenhuma informação sobre a existência da sessão do usuário na aplicação é armazenada.

Cada iteração do usuário com o sistema, do ponto de vista do servidor, é como se fosse a primeira.

Um exemplo de *token* utilizado é o JSON *Web Tokens*, [JWT](https://www.jwt.io/introduction#what-is-json-web-token). Este *token* é formado por três parcelas separadas por um ponto:
* *Header*: esta parcela é composta por duas parte, o tipo do *token*, neste caso, JWT, e o nome do algoritimo de assinatura, exemplo:

```
{
    "alg":HS256,
    "TYP":"JWT"
}
```

* *Payload*: esta parcela são as informações adicionais, as quais podem ser informações de registro, informações públicas ou informações privadas, veja o exemplo:
```
{
    "sub":"1234567890",
    "name":"John Doe",
    "admin":true,
}
```
* *Signature*: para a terceira parcela, a assinatura, será necessário uma algoritmode criptografia, o *Header* e o *Payload* criptografados e uma chave (*secret*):
```bash
HMACSHA256(
    base64UrlEncode(header) + "." +
    base64UrlEncode(payload),
    secret)
``` 

O resultado disto é uma chave criptografada que pode ser facilmente passada do cliente para o servidor com fins de autenticação do usuário. A seguir, uma imagem exemplo desta chave retirada da documentação do JWT:

![alt text](imagens/jwt_token.png)

### Autenticação *Statefull*



### Autenticação Federada

# Ataque de Força Bruta

## Configuração do Ambiente

## Protocolos

# Conclusão

# Referências
