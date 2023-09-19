# spyware-rust

## Desenvolvimento:
TO-DO

## Projeto:
* Projeto de Prova de conceito para o desenvolvimento de malware's para que assim possamos aprender como evitá-los e reconhece-los;
* Este spyware faz parte de um projeto maior chamado Remote-Analyser, o qual é um sistema desenvolvido por mim, para coleta de dados suspeitos em computadores empresarias e/ou institucionais. Servindo assim, como um monitoramento mais eficiente do patrimônio destas entidades;
* Esse script que coleta os dados foi desenvolvido em Python usando diversas bibliotecas específicas para auxiliar no desenvolvimento. Esse script fica ativo e vai gerar um Alerta toda vez que algo suspeito seja digitado, se algum processo malicioso esteja rodando ou se tem alguma porta aberta com alguma aplicação suspeita, enviando os dados para a API Gateway. Os dados coletados são: o endereço MAC do PC, a frase digitada que gerou o Alerta, os processos ativos no sistema e um PrintScreen da tela do usuário. Após isso, o script faz login na API Gateway e usa o token gerado para salvar os dados na API.
* O script também tem integração com um modelo criado para detectar discurso de ódio, desenvolvido por mim, além de um Sniffer e um Scanner, para evitar sites indesejados e vulnerabilidades;
*  Recentemente foi feita uma integração com o ChatGPT para auxiliar na análise de discurso de ódio.

## Como utilizar:
TODO

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
