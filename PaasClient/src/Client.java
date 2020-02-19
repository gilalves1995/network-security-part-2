

import java.util.Calendar;
import java.util.List;
import java.util.Map;

import exceptions.UntrustablePlatformException;
import paas_client.ClientAttestProtocol;
import paas_client.LocalIndex;
import paas_client.Redis;
import utils.ConfigParser;

public class Client {
	
	// Configuration file
	private static final String CONFIGURATION_FILE = "CLIENT.conf";
	
	// Configuration fields 
	private static final String KEYSTORE_FILE = "KEYSTORE_FILE";
	private static final String KEYSTORE_TYPE = "KEYSTORE_TYPE";
	private static final String KEYSTORE_PASS = "KEYSTORE_PASS";
	private static final String ALIAS = "KEY_ALIAS";
	private static final String REDIS_KEYSTORE_FILE = "REDIS_KEYSTORE_FILE";
	private static final String REDIS_KEYSTORE_TYPE = "REDIS_KEYSTORE_TYPE";
	private static final String REDIS_KEYSTORE_PASS = "REDIS_KEYSTORE_PASS";
	private static final String MAC_ALIAS = "MAC_KEY_ALIAS";
	private static final String ENCRYPTION_ALIAS = "ENCRYPTION_KEY_ALIAS";
	private static final String VMS_ADDRESS = "VMS_ADDRESS";
	private static final String VMS_PORT = "VMS_PORT";
	private static final String VMS_ALIAS = "VMS_ALIAS";
	private static final String GOS_ADDRESS = "GOS_ADDRESS";
	private static final String GOS_PORT = "GOS_PORT";
	private static final String GOS_ALIAS = "GOS_ALIAS";
	private static final String REDIS_ADDRESS = "REDIS_ADDRESS";
	
	// State files 
	private static final String VMS_MODULE_STATE = "vms-module-state.txt";
	private static final String GOS_MODULE_STATE = "gos-module-state.txt";
	
	// Messages
	private static final String TRUSTABLE_APP_LEVEL = "Platform was verified on application level and it's trustable.";
	private static final String TRUSTABLE_GUESTOS_LEVEL = "Platform was verified on operating system level and it's trustable.";
	private static final String REDIS_BEGIN = "Connecting to Redis key-value store...";
	private static final String BENCHMARK_BEGIN = "Benchmark will start executing...";
	private static final String BENCHMARK_END = "Benchmark execution finished.";
	
	private static final int TOTAL_OPERATIONS = 100;
	
	public static void main(String[] args) {
		
		Map<String, String> config = ConfigParser.parse(CONFIGURATION_FILE);
		
		String keystoreFile = config.get(KEYSTORE_FILE);
		String keystoreType = config.get(KEYSTORE_TYPE);
		String keystorePass = config.get(KEYSTORE_PASS);
		String alias = config.get(ALIAS);
		String redisKeystoreFile = config.get(REDIS_KEYSTORE_FILE);
		String redisKeystoreType = config.get(REDIS_KEYSTORE_TYPE);
		String redisKeystorePass = config.get(REDIS_KEYSTORE_PASS);
		
		String macKeyAlias = config.get(MAC_ALIAS);
		String encryptionKeyAlias = config.get(ENCRYPTION_ALIAS);
		
		String vmsAddress = config.get(VMS_ADDRESS);
		int vmsPort = Integer.parseInt(config.get(VMS_PORT));
		String vmsAlias = config.get(VMS_ALIAS);
		
		String gosAddress = config.get(GOS_ADDRESS);
		int gosPort = Integer.parseInt(config.get(GOS_PORT));
		String gosAlias = config.get(GOS_ALIAS);
		
		String redisAddress = config.get(REDIS_ADDRESS);
		
		
		Thread vmsThread = new Thread() {
			public void run() {
				try {
					ClientAttestProtocol vmsAttest = new ClientAttestProtocol(vmsAddress, vmsPort, VMS_MODULE_STATE, 
							keystoreFile, keystoreType, keystorePass, vmsAlias);
					vmsAttest.handleTLSConnection();
					vmsAttest.sendAuditRequest();
					boolean isAppLevelTrustable = vmsAttest.receiveAuditResponse();
					
					if(!isAppLevelTrustable) 
						throw new UntrustablePlatformException();
						
					System.out.println(TRUSTABLE_APP_LEVEL);
				} catch (Exception e) {
					System.out.println(e.getMessage());
					System.exit(1);	
				}
			}
		};
		
		Thread gosThread = new Thread() {
			public void run() {
				try {
					ClientAttestProtocol gosAttest = new ClientAttestProtocol(gosAddress, gosPort, GOS_MODULE_STATE,
							keystoreFile, keystoreType, keystorePass, gosAlias);
					gosAttest.handleTLSConnection();
					gosAttest.sendAuditRequest();
					boolean isGuestOSLeveltrustable = gosAttest.receiveAuditResponse();
					
					if(!isGuestOSLeveltrustable)
						throw new UntrustablePlatformException();
					
					
					System.out.println(TRUSTABLE_GUESTOS_LEVEL);
				} catch(Exception e) {
					System.out.println(e.getMessage());
					System.exit(1);
				}
			}
		};
		

		System.out.println(REDIS_BEGIN);
		Redis redis = new Redis(redisAddress, redisKeystoreFile, redisKeystoreType, redisKeystorePass, keystoreFile, 
				keystoreType, keystorePass, alias, macKeyAlias, encryptionKeyAlias);
		
		redis.connect();
		redis.flushAll();
		redis.populateRedis();
		
		System.out.println("Getting all entries for salary 1050...");
        List<String> entries = redis.getAllEntries(LocalIndex.SALARY, "1050");
        for (String entry : entries) {
            System.out.println("\tGot: " + entry);
        }
		
		System.out.println(BENCHMARK_BEGIN);
		
		vmsThread.start();
		gosThread.start();
		
		long begin = Calendar.getInstance().getTimeInMillis();
		
		try {
			vmsThread.join();
			gosThread.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		redis.benchmark(Redis.GET);
		redis.benchmark(Redis.SET);
		redis.benchmark(Redis.ERASE);
		
		long elapsed = Calendar.getInstance().getTimeInMillis() - begin;
        System.out.println("Benchmark result: " + ((1000 * 3 * TOTAL_OPERATIONS) / elapsed) + " ops/s");

		System.out.println(BENCHMARK_END);
		redis.disconnect();
		
	}
}


