package kdc;

import java.util.HashMap;
import java.util.Map;

/*
 * Database class for storing user credentials and service keys
 * Simulates a secure database for the KDC
 */
public class Database {
    private Map<String, byte[]> userKeys;        // username, password -> secret key
    private Map<String, byte[]> serviceKeys;     // service ID -> secret key
    
    public Database() {
        this.userKeys = new HashMap<>();
        this.serviceKeys = new HashMap<>();
        
        initializeDefaultData();    // Initialize with default users and services

    }
    
    /* Initialize database with default users and services */
    private void initializeDefaultData() {
        // Add default users
        addUser("alice", "password123");
        addUser("bob", "password456");
        addUser("charlie", "password789");
        
        // Add TGS service - using predictable key generation for demo
        addService("tgs", generateServiceKeyFromId("tgs"));
        
        // Add application services - using predictable key generation
        addService("fileserver", generateServiceKeyFromId("fileserver"));
        
        System.out.println("[Database] Initialized with default users and services");
    }
    
    /* Add a new user to the database */
    public void addUser(String username, String password) {
        byte[] key = deriveKeyFromPassword(password);
        userKeys.put(username, key);
        System.out.println("[Database] Added user: " + username);
    }
    
    /* Add a new service to the database */
    public void addService(String serviceId, byte[] key) {
        serviceKeys.put(serviceId, key);
        System.out.println("[Database] Added service: " + serviceId);
    }
    
    /* Get user's secret key */
    public byte[] getUserKey(String username) {
        return userKeys.get(username);
    }
    
    /* Get service's secret key */
    public byte[] getServiceKey(String serviceId) {
        return serviceKeys.get(serviceId);
    }
    
    /* Check if user exists */
    public boolean userExists(String username) {
        return userKeys.containsKey(username);
    }
    
    /* Check if service exists */
    public boolean serviceExists(String serviceId) {
        return serviceKeys.containsKey(serviceId);
    }
    
    /* Derive a key from password using simple hash */
    private byte[] deriveKeyFromPassword(String password) {
        try {
            byte[] passwordBytes = password.getBytes("UTF-8");
            byte[] key = new byte[16]; // 128-bit key
            
            for (int i = 0; i < key.length; i++) {
                key[i] = (byte) (passwordBytes[i % passwordBytes.length] ^ (i * 7));
            }
            
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive key from password", e);
        }
    }
    
    /* Generate service key from service ID */
    private byte[] generateServiceKeyFromId(String serviceId) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(serviceId.getBytes("UTF-8"));
            byte[] key = new byte[16]; // Use first 16 bytes for AES-128
            System.arraycopy(hash, 0, key, 0, 16);
            
            System.out.println("[Database] Generated key for service: " + serviceId);
            
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate service key from ID", e);
        }
    }
    
    /* Generate a random session key */
    public byte[] generateSessionKey() {
        byte[] key = new byte[16]; // 128-bit key
        //random.nextBytes(key);
        return key;
    }
}