# spyware-rust

## Desenvolvimento:
Este repositório contém um programa em Rust que funciona como um keylogger (registrador de teclas) e detector de ameaças. O código utiliza várias bibliotecas e módulos para realizar tarefas específicas. Abaixo está uma explicação do que foi usado e para que serve cada parte do código.

### Bibliotecas e Módulos Utilizados

- `winapi`: Utilizado para interagir com a API do Windows, permitindo o acesso a funcionalidades do sistema operacional Windows.

- `mac_address`: Utilizado para obter o endereço MAC da máquina, que pode ser usado para identificação única.

- `std::sync::Arc` e `std::sync::Mutex`: Utilizados para criar estruturas de dados compartilhadas entre threads de forma segura, permitindo o paralelismo controlado.

- `std::thread`: Usado para criação e gerenciamento de threads. O código possui várias threads que executam tarefas simultaneamente.

- `std::time::Duration`: Usado para especificar durações de tempo, como intervalos de espera entre verificações.

- `reqwest`: Biblioteca para fazer requisições HTTP, utilizada para se comunicar com servidores remotos.

- `serde` e `serde_json`: Utilizados para serialização e desserialização de dados JSON, permitindo o processamento de respostas de APIs web.

- `std::fs::File`: Usado para operações de leitura e escrita de arquivos, como leitura de listas de palavras proibidas.

- `std::collections::HashMap` e `std::collections::HashSet`: Utilizados para armazenar dados em estruturas de mapeamento e conjuntos.

- `reqwest::header::HeaderMap`: Usado para manipulação de cabeçalhos HTTP em requisições.

- `std::ptr` e `std::mem`: Utilizados para trabalhar com ponteiros e gerenciamento de memória.

- `winapi::um::tlhelp32::*` e `winapi::um::handleapi::*`: Módulos para interagir com a API do Windows relacionada a processos e handles.

- `image` e `win_screenshot::prelude::capture_display`: Biblioteca para processamento de imagens e captura de tela no Windows.

- `base64`: Utilizado para codificação e decodificação de dados em formato Base64.

- `tokio`: Biblioteca para programação assíncrona em Rust, utilizada para comunicação TCP assíncrona.

- `url::form_urlencoded`: Usado para codificar dados em formato de formulário URL.

- `serde_derive::Deserialize`: Usado para derivar automaticamente implementações de `Deserialize` para estruturas de dados.

### Funcionalidades Principais

O programa possui as seguintes funcionalidades principais:

1. **Keylogger**: Registra as teclas pressionadas pelo usuário e monitora a atividade do teclado.

2. **Detector de Ameaças**: Verifica se a atividade do usuário contém palavras proibidas, processos maliciosos ou discurso de ódio.

3. **Comunicação com Servidor Remoto**: Envia alertas para um servidor remoto em caso de atividade suspeita.

4. **Captura de Tela**: Captura a tela do sistema e envia para o servidor remoto em caso de atividade suspeita.

5. **Atualização de Dados Auxiliares**: Atualiza listas de palavras proibidas, banners vulneráveis, processos maliciosos e sites bloqueados a partir de um servidor web.

### Uso e Configuração

Antes de executar o programa, é necessário configurar as seguintes variáveis:

- `username` e `password`: Credenciais de login para autenticação no servidor.

- URLs para atualização de dados auxiliares: URLs para obter as últimas listas de palavras proibidas, banners vulneráveis, processos maliciosos e sites bloqueados.

Certifique-se de configurar essas variáveis antes de compilar e executar o código.


## Projeto:
* Projeto de Prova de conceito para o desenvolvimento de malware's para que assim possamos aprender como evitá-los e reconhece-los;
* Este spyware faz parte de um projeto maior chamado Remote-Analyser, o qual é um sistema desenvolvido por mim, para coleta de dados suspeitos em computadores empresarias e/ou institucionais. Servindo assim, como um monitoramento mais eficiente do patrimônio destas entidades;
* Esse script que coleta os dados foi desenvolvido em Python usando diversas bibliotecas específicas para auxiliar no desenvolvimento. Esse script fica ativo e vai gerar um Alerta toda vez que algo suspeito seja digitado, se algum processo malicioso esteja rodando ou se tem alguma porta aberta com alguma aplicação suspeita, enviando os dados para a API Gateway. Os dados coletados são: o endereço MAC do PC, a frase digitada que gerou o Alerta, os processos ativos no sistema e um PrintScreen da tela do usuário. Após isso, o script faz login na API Gateway e usa o token gerado para salvar os dados na API.
* O script também tem integração com um modelo criado para detectar discurso de ódio, desenvolvido por mim, além de um Sniffer e um Scanner, para evitar sites indesejados e vulnerabilidades;
*  Recentemente foi feita uma integração com o ChatGPT para auxiliar na análise de discurso de ódio.

## Como utilizar:
 - Basta rodar com cargo run.

### OU

* A aplicação completa contendo todos os microserviços configurados pode ser obtida no [DockerHub](https://hub.docker.com/repository/docker/darlannoetzold/tcc-spyware/general).
* Para executá-lo de maneira mais fácil basta excutar os seguintes comandos:
```
docker container run --platform=linux/amd64 -it -p 8091:8091 -p 8090:8090 -p 5000:5000 -p 9091:9090 -p 3000:3000 --name=app -d darlannoetzold/tcc-spyware:4.0docker exec -itd app /init-spyware-api.sh
docker exec -itd app /init-remoteanalyser.sh
docker exec -itd app /init-handler-hatespeech.sh
```

---
## API:
* A API:
* Documentação da API:
<br>Link: https://spyware-api.herokuapp.com/swagger-ui/index.html
* Repositório no GitHub:
<br>Link: https://github.com/DarlanNoetzold/spyware-API

---
## API do HateSpeech:
* A API:
* Repositório no GitHub:
<br>Link: https://github.com/DarlanNoetzold/HateSpeech-portuguese

---
## Remote-Analyser
* Repositório no GitHub:
<br>Link: https://github.com/DarlanNoetzold/Remote-Analyser

---
⭐️ From [DarlanNoetzold](https://github.com/DarlanNoetzold)
