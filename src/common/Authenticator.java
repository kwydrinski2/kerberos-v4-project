package common;

import java.io.Serializable;

/*  Authenticator class
 *  Used to prove the client's identity
 *  Created fresh for each service request 
 */
public class Authenticator implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String clientId;
    private long timestamp;
    private byte[] encryptedData; // Encrypted authenticator content
    
    /* Constructor for creating a new authenticator */
    public Authenticator(String clientId, long timestamp) {
        this.clientId = clientId;
        this.timestamp = timestamp;
    }
    
    /* Constructor with additional fields */
    public Authenticator(String clientId, long timestamp, String clientAddress) {
        this.clientId = clientId;
        this.timestamp = timestamp;
        //this.clientAddress = clientAddress;
    }
    
    /* Default constructor for deserialization */ //delete?
    public Authenticator() {
    }
    
    /* Getters and Setters */
    public String getClientId() {
        return clientId;
    }
    
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
    
    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }
}