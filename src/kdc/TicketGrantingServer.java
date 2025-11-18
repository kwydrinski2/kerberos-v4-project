package kdc;

import common.Authenticator;
import common.CryptoUtils;
import common.Message;
import common.Ticket;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

/*
 * Ticket Granting Server (TGS)
 * Issues service tickets after validating TGT
 */
public class TicketGrantingServer {
    private Database database;
    private Map<String, Long> usedAuthenticators; // Track authenticators to prevent replay
    private static final long AUTHENTICATOR_VALIDITY = 5 * 60 * 1000; // 5 minutes
    private static final long SERVICE_TICKET_LIFETIME = 2 * 60 * 60 * 1000; // 2 hours
    private static final long MAX_CLOCK_SKEW = 2 * 60 * 1000; // 2 minutes
    
    public TicketGrantingServer(Database database) {
        this.database = database;
        this.usedAuthenticators = new HashMap<>();
        System.out.println("[TGS] Ticket Granting Server initialized");
    }
    
    /* Handle ticket granting request from client */
    public Message handleTicketRequest(Message request) {
        System.out.println("\n[TGS] Received ticket request");
        System.out.println("[TGS] Message: " + request);
        
        try {
            // Validate request type
            if (request.getType() != Message.MessageType.TGS_REQ) {
                return Message.createErrorMessage("Invalid message type for TGS");
            }
            
            String requestedServiceId = request.getServiceId();
            Ticket tgt = request.getTicket();
            Authenticator authenticator = request.getAuthenticator();
            int nonce = request.getNonce();
            
            // Validate inputs
            if (tgt == null || authenticator == null) {
                System.out.println("[TGS] ERROR: Missing TGT or Authenticator");
                return Message.createErrorMessage("Missing TGT or Authenticator");
            }
            
            // Validate service exists
            if (!database.serviceExists(requestedServiceId)) {
                System.out.println("[TGS] ERROR: Service not found: " + requestedServiceId);
                return Message.createErrorMessage("Service not found: " + requestedServiceId);
            }
            
            System.out.println("[TGS] Validating TGT...");
            
            // Decrypt and validate TGT
            byte[] tgsKey = database.getServiceKey("tgs");
            byte[] decryptedTGT = CryptoUtils.decrypt(tgt.getEncryptedData(), tgsKey);
            Ticket decryptedTicket = deserializeTicket(decryptedTGT);
            
            // Validate TGT expiration
            if (System.currentTimeMillis() > decryptedTicket.getExpirationTime()) {
                System.out.println("[TGS] ERROR: TGT has expired");
                return Message.createErrorMessage("TGT has expired");
            }
            
            String clientId = decryptedTicket.getClientId();
            byte[] sessionKey = decryptedTicket.getSessionKey();
            
            System.out.println("[TGS] TGT validated for client: " + clientId);
            System.out.println("[TGS] Validating authenticator...");
            
            // Decrypt and validate authenticator
            byte[] decryptedAuth = CryptoUtils.decrypt(
                authenticator.getEncryptedData(), 
                sessionKey
            );
            Authenticator decryptedAuthenticator = deserializeAuthenticator(decryptedAuth);
            
            // Validate authenticator client ID matches TGT
            if (!decryptedAuthenticator.getClientId().equals(clientId)) {
                System.out.println("[TGS] ERROR: Client ID mismatch");
                return Message.createErrorMessage("Client ID mismatch");
            }
            
            // Validate authenticator timestamp (prevent replay attacks)
            long authTimestamp = decryptedAuthenticator.getTimestamp();
            long currentTime = System.currentTimeMillis();
            long timeDiff = Math.abs(currentTime - authTimestamp);
            
            if (timeDiff > MAX_CLOCK_SKEW) {
                System.out.println("[TGS] ERROR: Authenticator timestamp too old");
                return Message.createErrorMessage("Authenticator timestamp invalid");
            }
            
            // Check if authenticator has been used (replay attack)
            String authKey = clientId + ":" + authTimestamp;
            if (isAuthenticatorUsed(authKey)) {
                System.out.println("[TGS] ERROR: Authenticator already used (replay attack)");
                return Message.createErrorMessage("Replay attack detected");
            }
            
            usedAuthenticators.put(authKey, System.currentTimeMillis()); // mark authKey as used
            
            System.out.println("[TGS] Authenticator validated");
            System.out.println("[TGS] Generating service ticket for: " + requestedServiceId);
            
            // Generate new session key for Client-Service communication
            byte[] serviceSessionKey = database.generateSessionKey();
            
            // Create service ticket
            long issueTime = System.currentTimeMillis();
            long expirationTime = issueTime + SERVICE_TICKET_LIFETIME;
            
            Ticket serviceTicket = new Ticket(
                clientId,
                requestedServiceId,
                serviceSessionKey,
                issueTime,
                expirationTime
            );
            
            // Encrypt service ticket with service's secret key
            byte[] serviceKey = database.getServiceKey(requestedServiceId);
            byte[] encryptedServiceTicket = CryptoUtils.encrypt(
                serializeTicket(serviceTicket), 
                serviceKey
            );
            serviceTicket.setEncryptedData(encryptedServiceTicket);
            
            // Create encrypted session key package for client
            byte[] sessionKeyPackage = createSessionKeyPackage(
                serviceSessionKey, 
                nonce, 
                expirationTime
            );
            byte[] encryptedSessionKey = CryptoUtils.encrypt(sessionKeyPackage, sessionKey);
            
            System.out.println("[TGS] Successfully created service ticket");
            System.out.println("[TGS] Service ticket valid until: " + new java.util.Date(expirationTime));
            
            // Send TGS_REP
            return Message.createTGSReply(encryptedSessionKey, serviceTicket);
            
        } catch (Exception e) {
            System.err.println("[TGS] ERROR: " + e.getMessage());
            e.printStackTrace();
            return Message.createErrorMessage("Ticket request failed: " + e.getMessage());
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
    
    /* Deserialize ticket after decryption */
    private Ticket deserializeTicket(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Ticket ticket = (Ticket) ois.readObject();
        ois.close();
        return ticket;
    }
    
    /* Deserialize authenticator after decryption */
    private Authenticator deserializeAuthenticator(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Authenticator auth = (Authenticator) ois.readObject();
        ois.close();
        return auth;
    }
    
    /* Check if authenticator has been used */
    private boolean isAuthenticatorUsed(String authKey) {
        long currentTime = System.currentTimeMillis();
        usedAuthenticators.entrySet().removeIf(entry -> 
            currentTime - entry.getValue() > AUTHENTICATOR_VALIDITY
        );
        return usedAuthenticators.containsKey(authKey);
    }
}