package config;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/*
 * Configuration class for Kerberos V4 implementation
 * Manages network settings, security parameters, and system configurations
 */
public class Config {
    private static final String CONFIG_FILE = "kerberos.properties";
    private static Properties properties;
    
    // Default configuration values
    private static final String DEFAULT_KDC_HOST = "localhost";
    private static final int DEFAULT_KDC_PORT = 8888;
    private static final String DEFAULT_APP_SERVER_HOST = "localhost";
    private static final int DEFAULT_APP_SERVER_PORT = 9999;
    
    // Security settings
    private static final String DEFAULT_ENCRYPTION_ALGORITHM = "AES";
    private static final int DEFAULT_KEY_SIZE = 128; // bits
    private static final long DEFAULT_MAX_CLOCK_SKEW = 2 * 60 * 1000; // 2 minutes
    private static final long DEFAULT_TICKET_LIFETIME = 8 * 60 * 60 * 1000; // 8 hours
    private static final long DEFAULT_SERVICE_TICKET_LIFETIME = 2 * 60 * 60 * 1000; // 2 hours
    
    // Service IDs
    private static final String DEFAULT_TGS_ID = "tgs";
    private static final String DEFAULT_FILE_SERVER_ID = "fileserver";
    
    // Initialize configuration
    static {
        properties = new Properties();
        loadConfiguration();
    }
    
    /**
     * Load configuration from file, or use defaults if file doesn't exist
     */
    private static void loadConfiguration() {
        try (FileInputStream fis = new FileInputStream(CONFIG_FILE)) {
            properties.load(fis);
        } catch (IOException e) {
            System.out.println("[Config] Configuration file not found, using defaults");
            setDefaultConfiguration();
            saveConfiguration(); // Save defaults to file
        }
    }
    
    /**
     * Set default configuration values
     */
    private static void setDefaultConfiguration() {
        // Network settings
        properties.setProperty("kdc.host", DEFAULT_KDC_HOST);
        properties.setProperty("kdc.port", String.valueOf(DEFAULT_KDC_PORT));
        properties.setProperty("app.server.host", DEFAULT_APP_SERVER_HOST);
        properties.setProperty("app.server.port", String.valueOf(DEFAULT_APP_SERVER_PORT));
        
        // Security settings
        properties.setProperty("encryption.algorithm", DEFAULT_ENCRYPTION_ALGORITHM);
        properties.setProperty("key.size", String.valueOf(DEFAULT_KEY_SIZE));
        properties.setProperty("max.clock.skew", String.valueOf(DEFAULT_MAX_CLOCK_SKEW));
        properties.setProperty("ticket.lifetime", String.valueOf(DEFAULT_TICKET_LIFETIME));
        properties.setProperty("service.ticket.lifetime", String.valueOf(DEFAULT_SERVICE_TICKET_LIFETIME));
        
        // Service IDs
        properties.setProperty("service.tgs.id", DEFAULT_TGS_ID);
        properties.setProperty("service.fileserver.id", DEFAULT_FILE_SERVER_ID);
        
        // Connection settings
        properties.setProperty("connection.timeout", "30000"); // 30 seconds
        properties.setProperty("socket.timeout", "60000"); // 60 seconds
        
        // Debug settings
        properties.setProperty("debug.mode", "true");
        properties.setProperty("verbose.logging", "true");
    }
    
    /* Save configuration to file */
    public static void saveConfiguration() {
        try (FileOutputStream fos = new FileOutputStream(CONFIG_FILE)) {
            properties.store(fos, "Kerberos V4 Configuration");
            System.out.println("[Config] Configuration saved to " + CONFIG_FILE);
        } catch (IOException e) {
            System.err.println("[Config] Failed to save configuration: " + e.getMessage());
        }
    }
    
    // ===== Network Configuration Getters =====
    
    public static String getKDCHost() {
        return properties.getProperty("kdc.host", DEFAULT_KDC_HOST);
    }
    
    public static int getKDCPort() {
        return Integer.parseInt(properties.getProperty("kdc.port", String.valueOf(DEFAULT_KDC_PORT)));
    }
    
    public static String getAppServerHost() {
        return properties.getProperty("app.server.host", DEFAULT_APP_SERVER_HOST);
    }
    
    public static int getAppServerPort() {
        return Integer.parseInt(properties.getProperty("app.server.port", String.valueOf(DEFAULT_APP_SERVER_PORT)));
    }
    
    // ===== Service ID Getters =====
    
    public static String getTGSId() {
        return properties.getProperty("service.tgs.id", DEFAULT_TGS_ID);
    }
    
    public static String getFileServerId() {
        return properties.getProperty("service.fileserver.id", DEFAULT_FILE_SERVER_ID);
    }

    public static int getSocketTimeout() {
        return Integer.parseInt(properties.getProperty("socket.timeout", "60000"));
    }
}