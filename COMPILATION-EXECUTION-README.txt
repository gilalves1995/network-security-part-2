# Instruções de execução e compilação

# Existem 3 programas que têm que ser executados em separado (localizados na pasta src): Client.java, GOS_TPM.java, VMS_TPM.java

# Compilação 

1. cd PaasClient (directoria do projecto)
2. mvn clean e mvn install
3. javac src/*.java src/attestation_protocol/*.java src/exceptions/*.java src/paas_client/*.java src/security/*.java src/utils/*.java 


# Excecução 

# Para GOS_TPM 
java -cp target/classes/ GOS_TPM 

# Para VMS_TPM
java -cp target/classes/ VMS_TPM  

# Para Cliente 
java -cp target/classes/ Client  

(com o maven as classes compiladas ficam na pasta target/classes/ por isso pode ser necessário usar a flag -cp)
A directoria PaasClient inclui a imagem do Jedis-2.9.0 porque pode ser necessária adicionar às extensões do Java (/Library/Java/Extensions)


