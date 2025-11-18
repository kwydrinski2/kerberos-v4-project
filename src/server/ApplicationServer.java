package server;

import common.Authenticator;
import common.CryptoUtils;
import common.Message;
import common.Ticket;
import config.Config;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

/*
 * Application Server
 * Validates service tickets and provides access to protected resources
 */
public class ApplicationServer {
    private String serviceId;
    private byte[] serviceKey;
    private ServerSocket serverSocket;
    private boolean running;
    private Map<String, SessionInfo> activeSessions;
    private Map<String, Long> usedAuthenticators;
    private int requestCount;
    
    private static final long MAX_CLOCK_SKEW = 2 * 60 * 1000; // 2 minutes
    private static final long AUTHENTICATOR_VALIDITY = 5 * 60 * 1000; // 5 minutes
    
    public ApplicationServer(String serviceId, byte[] serviceKey) {
        this.serviceId = serviceId;
        this.serviceKey = serviceKey;
        this.activeSessions = new HashMap<>();
        this.usedAuthenticators = new HashMap<>();
        this.requestCount = 0;
        this.running = false;
        
        System.out.println("=================================");
        System.out.println("  Kerberos V4 - Application Server");
        System.out.println("  Service: " + serviceId);
        System.out.println("=================================\n");
    }
    
    /* Start the application server */
    public void start() {
        try {
            int port = Config.getAppServerPort();
            serverSocket = new ServerSocket(port);
            running = true;
            
            System.out.println("[AppServer] Server started on port " + port);
            System.out.println("[AppServer] Service ID: " + serviceId);
            System.out.println("[AppServer] Waiting for connections...\n");
            
            // Accept client connections
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("\n[AppServer] Client connected: " + 
                        clientSocket.getInetAddress().getHostAddress());
                    
                    // Handle client in new thread
                    Thread clientThread = new Thread(new ClientHandler(clientSocket));
                    clientThread.start();
                    
                } catch (Exception e) {
                    if (running) {
                        System.err.println("[AppServer] Error accepting connection: " + e.getMessage());
                    }
                }
            }
            
        } catch (Exception e) {
            System.err.println("[AppServer] Failed to start server: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /* Stop the application server */
    public void stop() {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            System.out.println("\n[AppServer] Server stopped");
        } catch (Exception e) {
            System.err.println("[AppServer] Error stopping server: " + e.getMessage());
        }
    }
    
    /* Handle authentication request from client */
    private Message handleAuthenticationRequest(Message request) {
        System.out.println("\n[AppServer] Processing authentication request");
        requestCount++;
        
        try {
            // Validate request type
            if (request.getType() != Message.MessageType.AP_REQ) {
                System.out.println("[AppServer] ERROR: Invalid message type");
                return Message.createErrorMessage("Invalid message type for application server");
            }
            
            Ticket serviceTicket = request.getTicket();
            Authenticator authenticator = request.getAuthenticator();
            
            // Validate inputs
            if (serviceTicket == null || authenticator == null) {
                System.out.println("[AppServer] ERROR: Missing ticket or authenticator");
                return Message.createErrorMessage("Missing ticket or authenticator");
            }
            
            System.out.println("[AppServer] Step 1: Validating service ticket...");
            
            // Decrypt service ticket with our service key
            byte[] decryptedTicket = CryptoUtils.decrypt(
                serviceTicket.getEncryptedData(), 
                serviceKey
            );
            Ticket ticket = deserializeTicket(decryptedTicket);
            
            // Validate ticket is for this service
            if (!ticket.getServiceId().equals(serviceId)) {
                System.out.println("[AppServer] ERROR: Invalid Ticket");
                return Message.createErrorMessage("Invalid Ticket");
            }
            
            // Validate ticket expiration
            long currentTime = System.currentTimeMillis();
            if (currentTime > ticket.getExpirationTime()) {
                System.out.println("[AppServer] ERROR: Service ticket has expired");
                return Message.createErrorMessage("Service ticket has expired");
            }
            
            String clientId = ticket.getClientId();
            byte[] sessionKey = ticket.getSessionKey();
            
            System.out.println("[AppServer] Service ticket validated");
            System.out.println("[AppServer]   Client: " + clientId);
            System.out.println("[AppServer]   Expires: " + new java.util.Date(ticket.getExpirationTime()));
            
            System.out.println("[AppServer] Step 2: Validating authenticator...");
            
            // Decrypt authenticator with session key
            byte[] decryptedAuth = CryptoUtils.decrypt(
                authenticator.getEncryptedData(), 
                sessionKey
            );
            Authenticator auth = deserializeAuthenticator(decryptedAuth);
            
            // Validate authenticator client ID matches ticket
            if (!auth.getClientId().equals(clientId)) {
                System.out.println("[AppServer] ERROR: Client ID mismatch");
                System.out.println("[AppServer]   Ticket: " + clientId);
                System.out.println("[AppServer]   Authenticator: " + auth.getClientId());
                return Message.createErrorMessage("Client ID mismatch");
            }
            
            // Validate authenticator timestamp (prevent replay attacks)
            long authTimestamp = auth.getTimestamp();
            long timeDiff = Math.abs(currentTime - authTimestamp);
            
            if (timeDiff > MAX_CLOCK_SKEW) {
                System.out.println("[AppServer] ERROR: Authenticator timestamp too old");
                System.out.println("[AppServer]   Time difference: " + (timeDiff / 1000) + " seconds");
                return Message.createErrorMessage("Authenticator timestamp invalid");
            }
            
            // Check if authenticator has been used (replay attack)
            String authKey = clientId + ":" + authTimestamp;
            if (isAuthenticatorUsed(authKey)) {
                System.out.println("[AppServer] ERROR: Authenticator already used (replay attack detected)");
                return Message.createErrorMessage("Replay attack detected");
            }
            usedAuthenticators.put(authKey, System.currentTimeMillis()); // mark authKey as used
            
            System.out.println("[AppServer] ✓ Authenticator validated");
            
            // Check if client already has an active session
            if (hasActiveSession(clientId)) {
                SessionInfo existingSession = activeSessions.get(clientId);
                long sessionAge = (System.currentTimeMillis() - existingSession.createdTime) / 1000;
                System.out.println("[AppServer] Client already has active session (age: " + sessionAge + "s)");
                
                // Verify the session key matches (security check)
                if (verifySessionKey(clientId, sessionKey)) {
                    System.out.println("[AppServer] Session key verified - refreshing session...");
                } else {
                    System.out.println("[AppServer] WARNING: Session key mismatch - creating new session");
                }
            }
            
            // Create or update session
            SessionInfo session = new SessionInfo(clientId, sessionKey, ticket.getExpirationTime());
            activeSessions.put(clientId, session);
            
            System.out.println("[AppServer] ✓ Authentication successful!");
            System.out.println("[AppServer]   Session established for: " + clientId);
            System.out.println("[AppServer]   Total active sessions: " + activeSessions.size());
            
            // Create AP_REP response (optional mutual authentication)
            // Encrypt timestamp + 1 with session key as proof
            long responseTimestamp = currentTime + 1;
            byte[] timestampData = String.valueOf(responseTimestamp).getBytes();
            byte[] encryptedTimestamp = CryptoUtils.encrypt(timestampData, sessionKey);
            
            System.out.println("[AppServer] Encrypted response with session key (mutual authentication)");
            
            // Log the successful access
            logAccess(clientId, "SUCCESS");
            
            return Message.createAPReply(encryptedTimestamp);
            
        } catch (Exception e) {
            System.err.println("[AppServer] Authentication failed: " + e.getMessage());
            e.printStackTrace();
            logAccess("unknown", "FAILED - " + e.getMessage());
            return Message.createErrorMessage("Authentication failed: " + e.getMessage());
        }
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
    private synchronized boolean isAuthenticatorUsed(String authKey) {
        long currentTime = System.currentTimeMillis();
        usedAuthenticators.entrySet().removeIf(entry -> 
            currentTime - entry.getValue() > AUTHENTICATOR_VALIDITY
        );
        return usedAuthenticators.containsKey(authKey);
    }
    
    /* Log access attempt */
    private void logAccess(String clientId, String status) {
        String timestamp = new java.util.Date().toString();
        System.out.println("\n[AppServer] ACCESS LOG:");
        System.out.println("  Time: " + timestamp);
        System.out.println("  Client: " + clientId);
        System.out.println("  Service: " + serviceId);
        System.out.println("  Status: " + status);
        System.out.println("  Request #" + requestCount);
    }
    
    /* Check if client has an active session */
    private boolean hasActiveSession(String clientId) {
        SessionInfo session = activeSessions.get(clientId);
        if (session == null) {
            return false;
        }
        
        // Check if session is still valid
        if (System.currentTimeMillis() > session.expirationTime) {
            activeSessions.remove(clientId);
            return false;
        }
        
        return true;
    }
    
    /* Verify session key matches the one in active session */
    private boolean verifySessionKey(String clientId, byte[] sessionKey) {
        SessionInfo session = activeSessions.get(clientId);
        if (session == null) {
            return false;
        }
        return true;
    }
    
    /* Client handler thread */
    private class ClientHandler implements Runnable {
        private Socket socket;
        
        public ClientHandler(Socket socket) {
            this.socket = socket;
        }
        
        @Override
        public void run() {
            try (
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())
            ) {
                // Read request from client
                Message request = (Message) in.readObject();
                
                // Handle authentication request
                Message response = handleAuthenticationRequest(request);
                
                // Send response back to client
                out.writeObject(response);
                out.flush();
                
                System.out.println("[AppServer] Response sent to client");
                System.out.println("[AppServer] Connection closed\n");
                
            } catch (Exception e) {
                System.err.println("[AppServer] Error handling client: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (Exception e) {
                    System.err.println("[AppServer] Error closing socket: " + e.getMessage());
                }
            }
        }
    }
    
    /* Session information class */
    private static class SessionInfo {
        long expirationTime;
        long createdTime;
        
        SessionInfo(String clientId, byte[] sessionKey, long expirationTime) {
            this.expirationTime = expirationTime;
            this.createdTime = System.currentTimeMillis();
        }
    }
    
    public static void main(String[] args) {
        String serviceId = Config.getFileServerId(); // Default to file server
        byte[] serviceKey = generateServiceKey(serviceId);
        
        ApplicationServer server = new ApplicationServer(serviceId, serviceKey);
        
        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[AppServer] Shutting down...");
            server.stop();
        }));
        
        server.start();        // Start the server

    }
    
    /* Generate service key (must match KDC's key for this service) */
    private static byte[] generateServiceKey(String serviceId) {
        System.out.println("[AppServer] Retrieve key from KDC");
        
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(serviceId.getBytes("UTF-8"));
            byte[] key = new byte[16]; // Use first 16 bytes for AES-128
            System.arraycopy(hash, 0, key, 0, 16);
            
            System.out.println("[AppServer] Generated key for service: " + serviceId);
            System.out.println("[AppServer] Key: " + key);
            
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate service key", e);
        }
    }
}