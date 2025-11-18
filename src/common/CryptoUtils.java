package common;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/*
 * CryptoUtils class for Kerberos V4 Protocol
 * Provides encryption and decryption utilities using AES
 */
public class CryptoUtils {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16; // 128 bits for AES
    private static final SecureRandom secureRandom = new SecureRandom();
    
    /* Encrypt data using AES with CBC mode */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes for AES-128");
        }
        
        // Generate random IV
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        
        // Create cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(data);
        
        // Prepend IV to encrypted data
        byte[] result = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, result, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, result, IV_SIZE, encrypted.length);
        
        return result;
    }
    
    /* Decrypt data using AES with CBC mode */
    public static byte[] decrypt(byte[] encryptedData, byte[] key) throws Exception {
        if (encryptedData == null || encryptedData.length <= IV_SIZE) {
            throw new IllegalArgumentException("Encrypted data is invalid");
        }
        
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes for AES-128");
        }
        
        // Extract IV from beginning of encrypted data
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedData, 0, iv, 0, IV_SIZE);
        
        // Extract actual encrypted data
        byte[] encrypted = new byte[encryptedData.length - IV_SIZE];
        System.arraycopy(encryptedData, IV_SIZE, encrypted, 0, encrypted.length);
        
        // Create cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        
        return decrypted;
    }
}