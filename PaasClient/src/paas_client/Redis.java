package paas_client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import redis.clients.jedis.Jedis;
import security.RedisSecurity;

public class Redis {

	// Benchmark Preferences
	public static final String GET = "GET";
	public static final String SET = "SET";
	public static final String ERASE = "ERASE";
	
	private static final int TOTAL_OPERATIONS = 100;
	

	// Database settings
	public static final int FIELD_NUMBER = 6;

	private static final String INITIAL_DATA_FILE = "db_initial_data.txt";
	private static final int REDIS_PORT = 6379;

	private Jedis jedis;
	private RedisSecurity security;
	private static LocalIndex index;
	private static List<String> seeds;

	public Redis(String serverAddress, String redisKeystoreFile, String redisKeystoreType, String redisKeystorePass,
			String clientKeystoreFile, String clientKeystoreType, String clientKeystorePass, String clientAlias,
			String macKeyAlias, String encryptionKeyAlias) {
		jedis = new Jedis(serverAddress, REDIS_PORT);

		security = new RedisSecurity(redisKeystoreFile, redisKeystoreType, redisKeystorePass, clientKeystoreFile,
				clientKeystoreType, clientKeystorePass, clientAlias, macKeyAlias, encryptionKeyAlias);
		
		index = new LocalIndex(TOTAL_OPERATIONS);
		seeds = new ArrayList<>(TOTAL_OPERATIONS);
	}

	// Connects to Redis key-value store
	public void connect() {
		jedis.connect();
	}

	// Disconnects from Redis key-value store
	public void disconnect() {
		jedis.disconnect();
	}

	// Flushes all the entries in Redis key-value store
	public void flushAll() {
		jedis.flushAll();
	}

	public String set(String key, String value) {
		try {
			String hashedKey = security.buildKey(key);
			String secureValue = security.encryptValue(value);
			return jedis.set(hashedKey, secureValue);
		} catch (Exception e) {
			return null;
		}
	}

	public Long del(String key) {
		String hashedKey = security.buildKey(key);
		SecureRandom r = new SecureRandom();
		try {
			String value = security.encryptValue(r.toString());
			jedis.set(hashedKey, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return jedis.del(hashedKey);
	}

	public String get(String key) {
		try {
			String hashedKey = security.buildKey(key);
			String encryptedValue = jedis.get(hashedKey);

			return security.decryptValue(encryptedValue);
		} catch (Exception e) {
			e.printStackTrace();
			return null; // TODO: Jedis error Code ?
		}
	}

	public List<String> getAll(String... keys) {
		List<String> values = new ArrayList<>(keys.length);
		for (String key : keys) {
			String value = get(key);
			values.add(value);
		}
		return values;
	}

	public void benchmark(final String OPERATION) {
		String[] keys = new String[TOTAL_OPERATIONS];
		index.getAllPrimaryKeys().toArray(keys);
		for (int i = 0; i < TOTAL_OPERATIONS; i++) {
			String res = null;
			String pk = keys[i];
			try {
				switch (OPERATION) {
				case GET:
					System.out.println(i + ". GET:");
					res = get(pk);
					break;
				case SET:
					System.out.println(i + ". SET:");
					String entry = seeds.get(i);
					res = putEntry(entry);
					break;
				case ERASE:
					System.out.println(i + ". REMOVE:");
					res = "" + del(pk);
					break;
				}
			} catch (Exception e) {
				e.printStackTrace();
				res = null;
			}
			System.out.println("\tGot: " + res);
		}
	}

	public void populateRedis() {
		try (BufferedReader br = new BufferedReader(new FileReader(new File(INITIAL_DATA_FILE)))) {
			String line;
			while ((line = br.readLine()) != null) {
				seeds.add(line);
				putEntry(line);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String putEntry(String entry) {
		String[] fields = entry.split("\\s+");
		index.setCc(fields[0], fields[0]);
		index.setEmissionDate(fields[1], fields[0]);
		index.setSalary(fields[2], fields[0]);
		index.setDepartment(fields[3], fields[0]);
		index.setNif(fields[4], fields[0]);

		return set(fields[0], entry);
	}

	public List<String> getAllEntries(int field, String fieldValue) {
		List<String> keys = index.getKeys(field, fieldValue);
		String[] keysArr = new String[keys.size()];
		keys.toArray(keysArr);

		return getAll(keysArr);
	}
}
