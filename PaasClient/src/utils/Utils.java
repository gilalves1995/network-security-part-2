package utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Utils {
	
	private static final String DIGITS = "0123456789abcdef";
	private static final String CIPHERSUITE_FILE = "ciphersuite.conf";
	private static final int SETTINGS_NUMBER = 5;
	
	
	// Transforms an array of bytes to an hexadecimal value
	public static String toHexa(byte [] bytes) {
		StringBuffer buf = new StringBuffer();
		for(int i = 0; i < bytes.length; i++) {
			int v = bytes[i] & 0xff;
			buf.append(DIGITS.charAt(v >> 4));
			buf.append(DIGITS.charAt(v & 0xf));
		}
		return buf.toString();
	}
	
	
	// Reads security configuration file
	public static String [] readCiphersuiteFile() {
		String [] settings = new String[SETTINGS_NUMBER];
		try {
			BufferedReader reader = new BufferedReader(new FileReader(CIPHERSUITE_FILE));
			int index = 0;
			String line;
			while ((line = reader.readLine()) != null) {
				String [] tmp = line.split(":");
				settings[index] = tmp[1].trim();
				index++;
			}
			reader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return settings;
	}
	
	
	// Reads a byte array and converts it to a String list
	public static List<String> readFromByteArray(byte [] bytes) {
		List <String> list = new ArrayList<String>();
		
		ByteArrayInputStream byteStream = new ByteArrayInputStream(bytes);
		DataInputStream inputStream = new DataInputStream(byteStream);
		try {
			while (inputStream.available() > 0) {
				String element = inputStream.readUTF();
				list.add(element);
			}
			return list;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Reads a String list and converts is to a byte array
	public static byte [] readFromList(List <String> list) {
		try {
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			DataOutputStream outStream = new DataOutputStream(byteStream);
			for(String line: list) {
				outStream.writeUTF(line);
			}
			return byteStream.toByteArray();
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static void sleep(long millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (int i = 0; i < arrays.length; i++)
            length += arrays[i].length;

        byte[] arr = new byte[length];

        for (int i = 0, currLength = 0; i < arrays.length; currLength += arrays[i++].length)
            System.arraycopy(arrays[i], 0, arr, currLength, arrays[i].length);

        return arr;
    }
	
	
}
