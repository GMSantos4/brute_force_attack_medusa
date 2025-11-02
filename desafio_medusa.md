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

Protocolo de autenticação é o processo que as aplicações *web* utilizam para confirmar que certo usuário poderá acessar ao conteúdo daquela aplicação *web*. Do ponto de vista do usuário, estes processos de autenticação são mais claros quando ele está tentando acessar um serviço por meio de suas credenciais (usuário e senha).

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

Na autenticação *stateful* as informações de sessão de um usuário após o *login* devem ser armazenadas. Ou seja, o servidor deve possuir um histórico das requisições realizadas pelo usuário durante a sessão. Este tipo de autenticação pode ser utilizada, por exemplo em serviços de e-mail ou serviços bancários.

Um exemplo de autenticação *stateful* é o [*Opaque Token*](https://docs.secureauth.com/ciam/en/opaque-token--concept,-purpose,-way-it-works.html#:~:text=Opaque%20Token%20Is-,The%20opaque%20token%20is%20a%20random%20unique%20string%20of%20characters%20issued,resource%20server%20calls%20the%20authorization%20server%20and%20requests%20the%20token%20introspection.,-With%20opaque%20tokens). Ele é *stateful*, pois, diferentemente do JWT, ele não carrega nenhuma informação no *token* em si.

Como vimos anteriormente, o JWT possui três informações criptografadas: *header*, *payload* e *signature*. Estas informações são decriptografadas no servidor de autorização que não armazena nenhuma informação da sessão do usuário.

Já o *Opaque Token* funciona como uma chave. Quanto o usuário faz o *login* no sistema, ele recebe o *Opaque Token*, que é uma *string* de caracteres aleatórios e únicos. Então, de posse desta chave (que não possui nenhuma informação das credenciais ou do usuário), o usuário pode realizar requisições aos outros serviços do sistema. 

Quando um serviço recebe uma requisição junto com o *token* ele não consegue permitir acesso apenas com o *token*, pois este não possui nenhuma identificação de quem é o usuário. Desta forma, o serviço faz uma consulta ao servidor de autorização e realiza uma *token introspection*. 

A *token introspection* nada mais é que uma requisição ao servidor de autorização solicitando informações como a validade do *token*, o nome do usuário, quais as permissões deste usuário, data de expiração, entre outros.

Observe que, neste caso, as informações solicitadas na *token introspection* estão armazenadas no servidor de autorização. Esta é a definição da autenticação *stateful*.

![alt text](imagens/autent_less_full.png)

### Autenticação Federada

O processo de autenticação federada é quando o serviço de autenticação de uma aplicação web é terceirizada para um provedor de identidades confiável. Um exemplo mais claro deste tipo de autenticação é o acesso a algumas aplicações por meio da autenticação da conta do *Google*. Neste caso, o *Google* é o provedor de identidades confiável.

# Ataque de Força Bruta

Ataques de força bruta são ataque que não exploram diretamente uma vulnerabilidade do sistema, mas sim vazamento de senhas ou a utilização de senhas fracas pelos usuários ou desenvolvedores do sistema. A seguir, apresento alguns destes ataques:
* Ataque de força bruta: parte da utilização de um conjunto de credenciais vazadas para tentar acesso a sistemas. Uma forma de impedir este tipo de ataque é limitar o número de tentativas de login do usuário;
* Ataque de força bruta pura (com permutação): este ataque não parte de uma lista de credenciais (*wordlist*), mas sim da combinações de caracteres. Este ataque se torna ineficaz se as senhas forem muito grandes ou complexas; e
* Ataque híbrido (managing rules): parte de uma *wordlist*, mas faz alterações que os humanos costumam fazer, exemplo, a senha "primeiro" se tornaria "pr1m31r0".

Outros ataques mais sofisticados são o *password spraying* e o *credential stuffing*:
* *Password Spraying*: neste ataque, em vez de se tentar várias senhas para um mesmo usuário, tenta-se a mesma senha para diversos usuários. Imagine que o atacante teve acesso à lista de e-mails de uma empresa. Ele pode, por exemplo, tentar *logar* no sistema com todos os e-mails utilizando a senha padrão "123456". Este ataque é mais sofisticados pois não alarma sistemas que são programados para bloquear o acesso após certo número de erro da senha; e
* Credential Stuffing: neste ataque, o atacante utiliza um conjunto de credenciais vazadas na internet para tentar acessar outros sistemas.Imagine que as credenciais do LinkedIn de um usuário vazou. A estratégia é usar estas credenciais para tentar acesso em outros sistemas, como Facebook, Instagra,, por exemplo.

## Configuração do Ambiente

Quanto ao processo de instalação do *Oracle VirtualBox* e das imagens iso do Kali e do Metasploitable2, isto não será discutido aqui. 

A única informação importante para a realização dos procedimentos a seguir é que ambas as máquinas deverão ser configuradas para estarem na rede local (*host-only*). Isto é configurado da seguinte forma:
1. Clique com o botão direito nas máquinas (ainda no *Oracle VirtualBox*) e acesse as configurações de cada máquina;
2. Acesse o menu "Rede"; e
3. Defina "Ligado a" como "Placa de rede exclusiva de hospedeiro (host-only)".

## Primeiros Contatos com Metasploitable2

O primeiro objetivo será a identificação do IP da máquina alvo. De acordo com a [documentação](https://nmap.org/book/man-target-specification.html#:~:text=Sometimes%20you%20wish%20to%20scan%20a%20whole%20network%20of%20adjacent%20hosts.%20For%20this%2C%20Nmap%20supports%20CIDR%2Dstyle%20addressing.%20You%20can%20append%20/%3Cnumbits%3E%20to%20an%20IP%20address%20or%20hostname%20and%20Nmap%20will%20scan%20every%20IP%20address%20for%20which%20the%20first%20%3Cnumbits%3E%20are%20the%20same%20as%20for%20the%20reference%20IP%20or%20hostname%20given.) do nmap, *sometimes you wish to scan a whole network of adjacent hosts. For this, Nmap supports CIDR-style addressing. You can append /\<numbits\> to an IP address or hostname and Nmap will scan every IP address for which the first \<numbits\> are the same as for the reference IP or hostname given.*

A intenção, então, será descobrir a máscara de rede e escanear todos os IPs desta rede usando a notação *CIDR-style addressing*. Apenas para fins de exemplo, suponha que o endereço de rede seja "192.168.1.0" e a mascará de rede seja "255.255.255.0". A notação CIDR, "192.168.1.0/24" quer dizer que os primeiros 24 bits do endereço, três octetos iniciais, são fixos.

Utilizando esta notação junto com o nmap torna possível escanear a rede em busca do nosso alvo. Observe na figura abaixo que a nossa máscara de rede (host-only) é 192.168.56.0 (*eth0*):

![alt text](imagens/net-mask.png)

Agora, basta varre a rede utilizando o seguinte comando:
```bash
nmap -sn 192.168.56.0/24
```

![alt text](imagens/nmap-net-scan.png)

## Protocolos

# Conclusão

# Referências
