package common;

import java.io.Serializable;
//import java.util.Arrays;

/*
 * Ticket class for Kerberos V4 Protocol
 * Represents both Ticket Granting Tickets (TGT) and Service Tickets
 */
public class Ticket implements Serializable {
    //private static final long serialVersionUID = 1L;
    
    private String clientId;        // client the ticket is issued to
    private String serviceId;       // service the ticket grants access to
    private byte[] sessionKey;      // session key for client-service communication
    private long issueTime;         // time the ticket was issued
    private long expirationTime;    // ticket expiration time
    private byte[] encryptedData;   // encrypted ticket content
    
    /* Constructor for creating a new ticket */
    public Ticket(String clientId, String serviceId, byte[] sessionKey, 
                  long issueTime, long expirationTime) {
        this.clientId = clientId;       
        this.serviceId = serviceId;     
        this.sessionKey = sessionKey;   
        this.issueTime = issueTime;     
        this.expirationTime = expirationTime;   
    }
    
    /* Default constructor for deserialization */
    public Ticket() {
    }
    
    /* Getters and Setters */

    public String getClientId() {
        return clientId;
    }
    
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    
    public String getServiceId() {
        return serviceId;
    }
    
    public void setServiceId(String serviceId) {
        this.serviceId = serviceId;
    }
    
    public byte[] getSessionKey() {
        return sessionKey;
    }
    
    public void setSessionKey(byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }
    
    public long getIssueTime() {
        return issueTime;
    }
    
    public void setIssueTime(long issueTime) {
        this.issueTime = issueTime;
    }
    
    public long getExpirationTime() {
        return expirationTime;
    }
    
    public void setExpirationTime(long expirationTime) {
        this.expirationTime = expirationTime;
    }
    
    public byte[] getEncryptedData() {
        return encryptedData;
    }
    
    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }
}