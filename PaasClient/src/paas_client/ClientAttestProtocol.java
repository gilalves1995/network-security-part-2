package paas_client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import exceptions.UnexpectedNonceException;
import exceptions.WrongOPCodeException;
import security.ClientSecurity;
import utils.Utils;

public class ClientAttestProtocol {
	
	// Protocol settings
	private static final byte OP_CODE = 0x00;
	private static final byte RESPONSE_CODE = 0X01;
	
	private final String serverAddress;
	private final int port;
	private final String stateFile;
	
	SecureRandom random;
	ClientSecurity security;
	byte [] lastNonceGenerated;
	String serverAlias;
	
	public ClientAttestProtocol(String serverAddress, int port, String stateFile, 
			String keystoreFile, String keystoreType, String keystorePass, String serverAlias) {
		
		this.serverAddress = serverAddress;
		this.port = port;
		this.stateFile = stateFile;
		random = new SecureRandom();
		security = new ClientSecurity(keystoreFile, keystoreType, keystorePass);
		lastNonceGenerated = null;
		this.serverAlias = serverAlias;
	}
	
	// Handles the whole TLS connection logic between this client and the specified endpoint
	public void handleTLSConnection() {
		try {
			security.handleTLSConnection(serverAddress, port);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// Sends an audit request to the specified endpoint
	public void sendAuditRequest() {
		lastNonceGenerated = security.generateNonce();
		
		byte [] myPublicNum = security.generatePublicNumber();
		
		byte [] payload = new byte [1 + myPublicNum.length + lastNonceGenerated.length];
		
		payload[0] = OP_CODE;
		System.arraycopy(myPublicNum, 0, payload, 1, myPublicNum.length);
		System.arraycopy(lastNonceGenerated, 0, payload, 1 + myPublicNum.length, lastNonceGenerated.length);

		String output = Base64.getEncoder().encodeToString(payload);
		security.writeToSocket(output);
	
		
	}
	
	// Waits and handles the audit response 
	public boolean receiveAuditResponse() throws IOException, WrongOPCodeException, UnexpectedNonceException {

		String encoded = security.readFromSocket();
		byte [] payload = Base64.getDecoder().decode(encoded);
		
		byte responseCode = payload[0];
		
		if(responseCode != RESPONSE_CODE) 
			throw new WrongOPCodeException();
		
		byte [] signatureSize = new byte [Integer.BYTES];
		System.arraycopy(payload, 1, signatureSize, 0, Integer.BYTES);
		
		ByteBuffer byteBuffer = ByteBuffer.wrap(signatureSize);
		byte [] signatureBytes = new byte[byteBuffer.getInt()];
		System.arraycopy(payload, 1 + Integer.BYTES, signatureBytes, 0, signatureBytes.length);
		
		byte [] signedItemsSize = new byte[Integer.BYTES];
		System.arraycopy(payload, 1 + Integer.BYTES + signatureBytes.length, signedItemsSize, 0, Integer.BYTES);
		
		byteBuffer = ByteBuffer.wrap(signedItemsSize);
		byte [] signedItems = new byte[byteBuffer.getInt()];
		System.arraycopy(payload, 1 + Integer.BYTES * 2 + signatureBytes.length, signedItems, 0, signedItems.length);
		
		byte [] proofs = new byte[payload.length - 1 - Integer.BYTES * 2 - signatureBytes.length - signedItems.length];
		System.arraycopy(payload, 1 + Integer.BYTES * 2 + signatureBytes.length + signedItems.length, proofs, 0, proofs.length);
		
		// Signature verification 
		PublicKey publickey = security.getPublicKey(serverAlias);
		security.verifySignature(signatureBytes, signedItems, publickey);
		
		// Get other party's public number 
		byte [] hisPublicNumber = new byte [signedItems.length - ClientSecurity.NONCE_SIZE];
		System.arraycopy(signedItems, 0, hisPublicNumber, 0, hisPublicNumber.length);
		
		byte [] nonce = new byte[ClientSecurity.NONCE_SIZE];
		System.arraycopy(signedItems, hisPublicNumber.length, nonce, 0, ClientSecurity.NONCE_SIZE);
		
		if(!security.isReceivedNonceValid(lastNonceGenerated, nonce))
			throw new UnexpectedNonceException();
		
		Key key = security.generateCommonKey(hisPublicNumber);
		byte [] decryptedProofs = security.decrypt(key, proofs);
		
		
		boolean trustable = isPlatformTrustable(decryptedProofs);		
		return trustable;
	}
	
	
	// Auxiliar method to verify if the platform is trustable. It consists in comparing the current state 
	// (obtained by the client previously) with the obtained proofs from the platform 
	private boolean isPlatformTrustable(byte [] proofs) {
		List <String> proofList = Utils.readFromByteArray(proofs);
		
		try {
			File file = new File(stateFile); 
			if(file.length() == 0) {
				BufferedWriter writer = new BufferedWriter(new FileWriter(stateFile));
			    for(String line: proofList) 
			    	writer.write(line + "\n");
			    
			    writer.close();
			    return true;
			} else {
				List <String> tmp = new ArrayList<String>();
				BufferedReader reader = new BufferedReader(new FileReader(stateFile));
				String line;
				while((line = reader.readLine()) != null) {
					tmp.add(line);
				}
				reader.close();
				return MessageDigest.isEqual(proofs, Utils.readFromList(tmp));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	
	
	
	
	
}
