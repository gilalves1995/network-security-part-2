import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.util.Map;

import attestation_protocol.ServerAttestProtocol;
import utils.ConfigParser;

public class VMS_TPM {
	
	// Configuration file
	private static final String CONFIGURATION_FILE = "VMS_TPM.conf";
	
	// Endpoint and keystore configuration fields
	private static final String FILE_FIELD = "KEYSTORE_FILE";
	private static final String TYPE_FIELD = "KEYSTORE_TYPE";
	private static final String PASS_FIELD = "KEYSTORE_PASS";
	private static final String ALIAS_FIELD = "KEY_ALIAS";
	private static final String ADDRESS_FIELD = "ADDRESS";
	private static final String PORT_FIELD = "PORT";
	
	
	// Shell commands script to get machine state
	private static final String VMS_PROOFS_SCRIPT = "vms-attest-proofs.sh";
	
	public static void main(String[] args) throws Exception {
		
		Map<String, String> config = ConfigParser.parse(CONFIGURATION_FILE);
		
		String keystoreFile = config.get(FILE_FIELD);
		String keystoreType = config.get(TYPE_FIELD);
		String keystorePass = config.get(PASS_FIELD);
		String alias = config.get(ALIAS_FIELD);
		String address = config.get(ADDRESS_FIELD);
		int port = Integer.parseInt(config.get(PORT_FIELD));
		
		
		

		System.out.println("The module VMS-TPM is running on address " + address + " and on port " + port + ".");
		

		ServerAttestProtocol protocol = new ServerAttestProtocol(address, port, keystoreFile, keystoreType, keystorePass, alias);
		protocol.handleTLSConnection();
			
		while( true ) {
			String request = protocol.waitForAuditRequest();
			if(request != null) {
				byte [] proofs = getProofs();
				String response = protocol.handleAuditRequest(request, proofs);
				protocol.sendAuditResponse(response);
			}
		}
	}
	
	
    private static byte [] getProofs() {
		try {
			String [] command = new String[] {"sh", VMS_PROOFS_SCRIPT};
			Process process = Runtime.getRuntime().exec(command);
			
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
			// To tranform list to byte array 
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			DataOutputStream outStream = new DataOutputStream(byteStream);
			
			String line;
			while((line = reader.readLine()) != null) {
				outStream.writeUTF(line);
			}
			byte [] proofs = byteStream.toByteArray();
			return proofs;
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	

}
