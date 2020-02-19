package utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class ConfigParser {
    
    public static Map<String, String> parse(String filename) {
        Map<String, String> config = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(new File(filename)))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();

                if (line.length() == 0)
                    continue;
                if (line.charAt(0) == '#')
                    continue;

                String[] configPair = line.split(":");
                config.put(configPair[0].toUpperCase(), configPair[1].trim());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return config;
    }
}
