package kdc;

import common.CryptoUtils;
import common.Message;
import common.Ticket;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

/*
 * Authentication Server (AS)
 * Handles initial authentication requests and issues Ticket Granting Tickets (TGT)
 */
public class AuthenticationServer {
    private Database database;
    private Map<Integer, Long> usedNonces; // Track nonces to prevent replay attacks
    private static final long TICKET_LIFETIME = 8 * 60 * 60 * 1000; // 8 hours
    
    public AuthenticationServer(Database database) {
        this.database = database;
        this.usedNonces = new HashMap<>();
        System.out.println("[AS] Authentication Server initialized");
    }
    
    /* Handle authentication request from client */
    public Message handleAuthenticationRequest(Message request) {
        System.out.println("\n[AS] Received authentication request");
        System.out.println("[AS] Message: " + request);
        
        try {
            // Validate request type
            if (request.getType() != Message.MessageType.AS_REQ) {
                return Message.createErrorMessage("Invalid message type for AS");
            }
            
            String clientId = request.getClientId();
            String tgsId = request.getServiceId();
            int nonce = request.getNonce();
            
            // Validate client exists
            if (!database.userExists(clientId)) {
                System.out.println("[AS] ERROR: User does not exist: " + clientId);
                return Message.createErrorMessage("User not found: " + clientId);
            }
            
            // Validate TGS exists
            if (!database.serviceExists(tgsId)) {
                System.out.println("[AS] ERROR: TGS service not found: " + tgsId);
                return Message.createErrorMessage("TGS service not found: " + tgsId);
            }
        
            // Mark nonce as used
            markNonceAsUsed(nonce);
            
            System.out.println("[AS] Generating session key and TGT for client: " + clientId);
            
            // Generate session key for Client-TGS communication
            byte[] sessionKey = database.generateSessionKey();
            
            // Create Ticket Granting Ticket (TGT)
            long issueTime = System.currentTimeMillis();
            long expirationTime = issueTime + TICKET_LIFETIME;
            
            Ticket tgt = new Ticket(
                clientId,
                tgsId,
                sessionKey,
                issueTime,
                expirationTime
            );
            
            // Encrypt TGT with TGS's secret key
            byte[] tgsKey = database.getServiceKey(tgsId);
            byte[] encryptedTGT = CryptoUtils.encrypt(serializeTicket(tgt), tgsKey);
            tgt.setEncryptedData(encryptedTGT);
            
            // Create encrypted session key package for client
            // Contains: session key and nonce
            byte[] sessionKeyPackage = createSessionKeyPackage(sessionKey, nonce, expirationTime);
            byte[] clientKey = database.getUserKey(clientId);
            byte[] encryptedSessionKey = CryptoUtils.encrypt(sessionKeyPackage, clientKey);
            
            System.out.println("[AS] Successfully created TGT for: " + clientId);
            System.out.println("[AS] TGT valid until: " + new java.util.Date(expirationTime));
            
            // Send AS_REP
            return Message.createASReply(encryptedSessionKey, tgt);
            
        } catch (Exception e) {
            System.err.println("[AS] ERROR: " + e.getMessage());
            e.printStackTrace();
            return Message.createErrorMessage("Authentication failed: " + e.getMessage());
        }
    }
    
    /* Create session key package with nonce for verification */
    private byte[] createSessionKeyPackage(byte[] sessionKey, int nonce, long expiration) 
            throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        
        oos.writeInt(sessionKey.length);
        oos.write(sessionKey);
        oos.writeInt(nonce);
        oos.writeLong(expiration);
        
        oos.close();
        return baos.toByteArray();
    }
    
    /* Serialize ticket for encryption */
    private byte[] serializeTicket(Ticket ticket) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(ticket);
        oos.close();
        return baos.toByteArray();
    }
    
    /* Mark nonce as used */
    private void markNonceAsUsed(int nonce) {
        usedNonces.put(nonce, System.currentTimeMillis());
    }
}