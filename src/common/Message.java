package common;

import java.io.Serializable;

/*
 * Message class for Kerberos V4 Protocol
 * Handles all message types exchanged between Client, KDC (AS/TGS), and Application Server
 */
public class Message implements Serializable {
    //private static final long serialVersionUID = 1L;
    
    public enum MessageType {
        AS_REQ,          // Authentication Service Request
        AS_REP,          // Authentication Service Reply
        
        TGS_REQ,         // Ticket Granting Service Request
        TGS_REP,         // Ticket Granting Service Reply
        
        AP_REQ,          // Application Request
        AP_REP,          // Application Reply
        
        ERROR            // Error Message
    }
    
    private MessageType type;
    private String clientId;
    private String serviceId;
    private byte[] encryptedData;
    private Ticket ticket;
    private Authenticator authenticator;
    private long timestamp;
    private int nonce;
    private String errorMessage;
    
    // Constructor
    public Message(MessageType type) {
        this.type = type;
        this.timestamp = System.currentTimeMillis();
    }
    
    // === AS_REQ Message ===
    public static Message createASRequest(String clientId, String tgsId, int nonce) {
        Message msg = new Message(MessageType.AS_REQ);
        msg.setClientId(clientId);
        msg.setServiceId(tgsId);
        msg.setNonce(nonce);
        return msg;
    }
    
    // === AS_REP Message ===
    public static Message createASReply(byte[] encryptedSessionKey, Ticket tgsTicket) {
        Message msg = new Message(MessageType.AS_REP);
        msg.setEncryptedData(encryptedSessionKey);
        msg.setTicket(tgsTicket);
        return msg;
    }
    
    // === TGS_REQ Message ===
    public static Message createTGSRequest(String serviceId, Ticket tgsTicket, 
                                          Authenticator auth, int nonce) {
        Message msg = new Message(MessageType.TGS_REQ);
        msg.setServiceId(serviceId);
        msg.setTicket(tgsTicket);
        msg.setAuthenticator(auth);
        msg.setNonce(nonce);
        return msg;
    }
    
    // === TGS_REP Message ===
    public static Message createTGSReply(byte[] encryptedSessionKey, Ticket serviceTicket) {
        Message msg = new Message(MessageType.TGS_REP);
        msg.setEncryptedData(encryptedSessionKey);
        msg.setTicket(serviceTicket);
        return msg;
    }
    
    // === AP_REQ Message ===
    public static Message createAPRequest(Ticket serviceTicket, Authenticator auth) {
        Message msg = new Message(MessageType.AP_REQ);
        msg.setTicket(serviceTicket);
        msg.setAuthenticator(auth);
        return msg;
    }
    
    // === AP_REP Message ===
    public static Message createAPReply(byte[] encryptedTimestamp) {
        Message msg = new Message(MessageType.AP_REP);
        msg.setEncryptedData(encryptedTimestamp);
        return msg;
    }
    
    // === ERROR Message ===
    public static Message createErrorMessage(String errorMessage) {
        Message msg = new Message(MessageType.ERROR);
        msg.setErrorMessage(errorMessage);
        return msg;
    }
    
    // Getters and Setters
    public MessageType getType() {
        return type;
    }
    
    public void setType(MessageType type) {
        this.type = type;
    }
    
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
    
    public byte[] getEncryptedData() {
        return encryptedData;
    }
    
    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }
    
    public Ticket getTicket() {
        return ticket;
    }
    
    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }
    
    public Authenticator getAuthenticator() {
        return authenticator;
    }
    
    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
    
    public int getNonce() {
        return nonce;
    }
    
    public void setNonce(int nonce) {
        this.nonce = nonce;
    }
    
    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}