package attestation_protocol;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.util.Base64;

import exceptions.WrongOPCodeException;
import security.ServerSecurity;

public class ServerAttestProtocol {
	
	// Protocol Settings
	private static final byte REQUEST_CODE = 0x00;
	private static final byte OP_CODE = 0X01;
	
	private final String address;
	private final int port;

	ServerSecurity security;
	
	public ServerAttestProtocol(String address, int port, String keystoreFile, String keystoreType, String keystorePass, String alias) {
		this.address = address;
		this.port = port;
		security = new ServerSecurity(keystoreFile, keystoreType, keystorePass, alias);
	}
	
	// Handles the whole TLS connection logic between this server and the client
	public void handleTLSConnection() {
		try {
			security.handleTLSConnection(address, port);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
  
	// Handles an audit request 
	public String handleAuditRequest(String request, byte [] proofs) throws WrongOPCodeException {
		
		byte [] payload = Base64.getDecoder().decode(request);
		byte opcode = payload[0];
		
		if(opcode != REQUEST_CODE) 
			throw new WrongOPCodeException();

		int publicNumberLength = payload.length - ServerSecurity.NONCE_SIZE - 1;
		
		byte [] hisPublicNumber = new byte[publicNumberLength];  
		byte [] nonce = new byte[ServerSecurity.NONCE_SIZE];
		
		System.arraycopy(payload, 1, hisPublicNumber, 0, publicNumberLength);
		System.arraycopy(payload, 1 + publicNumberLength, nonce, 0, nonce.length);
		
		String response = buildAuditResponse(hisPublicNumber, nonce, proofs);
		return response;
	}
	
	
	// Auxiliar method used to build a response string
	private String buildAuditResponse(byte [] hisPublicNumber, byte [] nonce, byte [] proofs) {
		byte [] incrementedNonce = ServerSecurity.incrementNonce(nonce); 
		byte [] myPublicNumber = security.generatePublicNumber();
		byte [] toSign = new byte [myPublicNumber.length + incrementedNonce.length];
		
		System.arraycopy(myPublicNumber, 0, toSign, 0, myPublicNumber.length);
		System.arraycopy(incrementedNonce, 0, toSign, myPublicNumber.length, incrementedNonce.length);
		
		PrivateKey privateKey = security.getPrivateKey();
		
		byte [] signature = security.doSignature(toSign, privateKey);
		
		Key encryptionKey = security.generateCommonKey(hisPublicNumber);
		
		byte [] ciphertext = security.encrypt(encryptionKey, proofs);
		
		byte [] payload = new byte [1 + signature.length + ciphertext.length];
		payload[0] = OP_CODE;
		System.arraycopy(signature, 0, payload, 1, signature.length);
		System.arraycopy(ciphertext, 0, payload, 1 + signature.length, ciphertext.length);
		
		String output = Base64.getEncoder().encodeToString(payload);
		return output;
	}
	
	// Listens to an audit request from the client
	public String waitForAuditRequest() {
		try {
			return security.readFromSocket();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Sends an audit response 
	public void sendAuditResponse(String output) {
		security.writeToSocket(output);
	}
	
}
