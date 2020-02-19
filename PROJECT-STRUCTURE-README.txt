# Estrutura do projecto 

# O projecto é dividido nos seguintes packages: 

- default package: contém os programas Client.java, TPM_GOS.java e TPM_VMS.java 
- attestation_protocol: toda a funcionalidade necessário para o protocolo de atestação do lado do servidor (módulos TPM)
- exceptions: todas as excepções necessárias (ataques à integridade, autenticidade, plataforma não confiável, etc...)
- paas_client: toda a funcionalidade necessária do lado do cliente como acesso ao Redis key-value store e lógica de interação com os módulos TPM
- security: engloba todas as classes necessárias que utilizem funcionalidades de segurança
- utils: métodos auxiliares utilizados no projecto 

# Classes do package security 
- Protocol security: classe abstracta que engloba todas as funcionalidades de segurança comuns aos módulos TPM e cliente 
- ServerSecurity: funcionalidades especificas ao servidor (métodos especificos aos módulos TPM utilizados para assegurar segurança na comunicação com o cliente)
- ClientSecurity: funcionalidades especificas ao cliente (métodos especificos ao cliente utilizados para assegurar segurança na comunicação com os módulos TPM)
- RedisSecurity: classe que encapsula toda a lógica para armazenar e obter dados do Redis, armazenados de forma segura
- Keystore: classe que encapsula todas a lógica para obter (ou armazenar) dados numa keystone

# Classes do package paas_client
- ClientAttestProtocol: engloba toda a lógica do lado do cliente para comunicar com os Módulos TPM
- Redis: todas as funcionalidades referentes a uma key-value store Redis (GET, SET, ERASE)
- LocalIndex: faz a indexação das chaves aos vários parâmetros das entradas

# attestation_protocol
- ServerAttestProtocol: engloba toda a logica do lado dos módulos TPM para comunicar com o cliente 

# Classes do default_package 
GOS_TPM: lança um processo referente ao módulo TPM_GOS
VMS_TPM: lança um processo referente ao módulo TPM_VMS
Client: lança um processo referente ao cliente

# Ficheiros 
- VMS_TPM.conf : configurações do módulo VMS_TPM: endpoint, porto, dados da keystore referentes a esse módulo 
- GOS_TPM.conf : configurações do módulo GOS_TPM: endpoint, porto, dados da keystore referentes a esse módulo
- CLIENT.conf : configurações de um cliente: endpoints, portos e alias dos dois módulos (alias para conseguir obter a chave pública dos módulos), endpoint do Redis, configurações referentes a keystones utilizadas pelo cliente (uma para obter chaves para criptografia simétrica/mac para utilizar na comunicação com o Redis e outra utilizada na comunicação TLS com os módulos TPM) 
- vms_attest_proofs.sh : script que executa na máquina onde corre o módulo TPM_VMS para obter as provas de atestação enviadas para o cliente
- gos_attest_proofs.sh : script que executa na máquina onde corre o módulo TPM_GOS para obter as provas de atestação enviadas para o cliente
- vms-module-state.txt : ficheiro mantido pelo cliente que guarda o estado das provas obtidas pelo módulo TPM_VMS (para comparação futura com outras provas e identificar se a plataforma é segura)
- gos-module-state.txt : ficheiro mantido pelo cliente que guarda o estado das provas obtidas pelo módulo TPM_GOS (para comparação futura com outras provas e identificar se a plataforma é segura)
- db_initial_data.txt : ficheiro utilizado para popular a key-value store do Redis com dados iniciais
- ciphersuite.conf : ficheiro que contém parametrizações utilizadas na criptografia simétrica e macs para armazenar dados de forma segura no Redis 
- tls_ciphersuites.txt : ficheiro contém todas as ciphersuites utilizadas pelo protocolo TLS 