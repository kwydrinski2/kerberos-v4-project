package client;

import common.Authenticator;
import common.CryptoUtils;
import common.Message;
import common.Ticket;
import config.Config;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Random;
import java.util.Scanner;

/*
 * Kerberos Client
 * Handles authentication and service access using Kerberos V4 protocol
 */
public class KerberosClient {
    private String username;
    private byte[] userKey;
    private byte[] tgsSessionKey;
    private Ticket tgt;
    private Random random;
    private Scanner scanner;
    
    public KerberosClient() {
        this.random = new Random();
        this.scanner = new Scanner(System.in);
        
        System.out.println("=================================");
        System.out.println("  Kerberos V4 - Client");
        System.out.println("=================================\n");
    }
    
    /* Start the client application */
    public void start() {
        try {
            // Step 1: User login
            if (!login()) {
                System.out.println("Login failed. Exiting...");
                return;
            }
            
            // Step 2: Get TGT from Authentication Server
            if (!getTGTFromAS()) {
                System.out.println("Failed to obtain TGT. Exiting...");
                return;
            }
            
            // Step 3: Main menu loop
            boolean running = true;
            while (running) {
                System.out.println("\n=================================");
                System.out.println("  Main Menu");
                System.out.println("=================================");
                System.out.println("1. Access File Server");
                System.out.println("2. Display Session Info");
                System.out.println("3. Exit");
                System.out.print("\nSelect an option: ");
                
                String choice = scanner.nextLine().trim();
                
                switch (choice) {
                    case "1":
                        accessService(Config.getFileServerId());
                        break;
                    case "2":
                        displaySessionInfo();
                        break;
                    case "3":
                        running = false;
                        System.out.println("\nGoodbye!");
                        break;
                    default:
                        System.out.println("Invalid option. Please try again.");
                }
            }
            
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    
    /* Step 1: User login - collect credentials */
    private boolean login() {
        System.out.println("=== User Login ===");
        System.out.print("Username: ");
        username = scanner.nextLine().trim();
        
        System.out.print("Password: ");
        String password = scanner.nextLine().trim();
        
        // Derive key from password
        userKey = deriveKeyFromPassword(password);
        
        System.out.println("\n[Client] Credentials collected for user: " + username);
        return true;
    }
    
    /* Step 2: Get Ticket Granting Ticket from Authentication Server */
    private boolean getTGTFromAS() {
        System.out.println("\n=== Requesting TGT from Authentication Server ===");
        
        try {
            // Generate nonce for freshness
            int nonce = random.nextInt(1000000);
            
            // Create AS_REQ message
            Message request = Message.createASRequest(
                username,
                Config.getTGSId(),
                nonce
            );
            
            System.out.println("[Client] Sending AS_REQ to KDC...");
            System.out.println("[Client] Requesting TGT for service: " + Config.getTGSId());
            
            // Send request to KDC
            Message response = sendToKDC(request);
            
            if (response.getType() == Message.MessageType.ERROR) {
                System.err.println("[Client] ERROR: " + response.getErrorMessage());
                return false;
            }
            
            if (response.getType() != Message.MessageType.AS_REP) {
                System.err.println("[Client] ERROR: Unexpected response type");
                return false;
            }
            
            System.out.println("[Client] Received AS_REP from KDC");
            
            // Decrypt session key package with user's key
            byte[] encryptedSessionKey = response.getEncryptedData();
            byte[] decryptedPackage = CryptoUtils.decrypt(encryptedSessionKey, userKey);
            
            // Extract session key and verify nonce
            SessionKeyPackage pkg = extractSessionKeyPackage(decryptedPackage);
            
            if (pkg.nonce != nonce) {
                System.err.println("[Client] ERROR: Nonce mismatch - possible attack!");
                return false;
            }
            
            // Store TGS session key and TGT
            tgsSessionKey = pkg.sessionKey;
            tgt = response.getTicket();
            
            System.out.println("[Client] Successfully obtained TGT!");
            System.out.println("[Client] TGT valid until: " + new java.util.Date(pkg.expiration));
            System.out.println("[Client] Single Sign-On enabled - you can now access multiple services");
            
            return true;
            
        } catch (Exception e) {
            System.err.println("[Client] Failed to get TGT: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /* Access a specific service */
    private void accessService(String serviceId) {
        System.out.println("\n=== Accessing Service ===");
        
        try {
            // Step 2: Get service ticket from TGS
            Ticket serviceTicket = getServiceTicketFromTGS(serviceId);
            if (serviceTicket == null) {
                System.out.println("Failed to obtain service ticket.");
                return;
            }
            
            // Step 3: Access application server with service ticket
            boolean success = accessApplicationServer(serviceId, serviceTicket);
            
            if (success) {
                System.out.println("\n[Client] Successfully accessed " + serviceId);
                System.out.println("[Client] Service session established!");
            } else {
                System.out.println("\n[Client] Failed to access " + serviceId);
            }
            
        } catch (Exception e) {
            System.err.println("[Client] Error accessing service: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Step 2: Get service ticket from Ticket Granting Server
     */
    private Ticket getServiceTicketFromTGS(String serviceId) {
        System.out.println("\n[Client] Step 1: Requesting service ticket from TGS...");
        
        try {
            // Generate nonce
            int nonce = random.nextInt(1000000);
            
            // Create authenticator
            Authenticator authenticator = new Authenticator(
                username,
                System.currentTimeMillis()
            );
            
            // Encrypt authenticator with TGS session key
            byte[] serializedAuth = serializeAuthenticator(authenticator);
            byte[] encryptedAuth = CryptoUtils.encrypt(serializedAuth, tgsSessionKey);
            authenticator.setEncryptedData(encryptedAuth);
            
            // Create TGS_REQ message
            Message request = Message.createTGSRequest(
                serviceId,
                tgt,
                authenticator,
                nonce
            );
            
            System.out.println("[Client] Sending TGS_REQ to KDC...");
            
            // Send request to KDC
            Message response = sendToKDC(request);
            
            if (response.getType() == Message.MessageType.ERROR) {
                System.err.println("TGS Request Error");
                return null;
            }
            
            if (response.getType() != Message.MessageType.TGS_REP) {
                System.err.println("[Client] ERROR: Unexpected response type");
                return null;
            }
            
            System.out.println("[Client] Received TGS_REP from KDC");
            
            // Decrypt service session key package with TGS session key
            byte[] encryptedSessionKey = response.getEncryptedData();
            byte[] decryptedPackage = CryptoUtils.decrypt(encryptedSessionKey, tgsSessionKey);
            
            // Extract service session key and verify nonce
            SessionKeyPackage pkg = extractSessionKeyPackage(decryptedPackage);
            
            if (pkg.nonce != nonce) {
                System.err.println("[Client] ERROR: Nonce mismatch - possible attack!");
                return null;
            }
            
            // Store service session key in ticket for later use
            Ticket serviceTicket = response.getTicket();
            serviceTicket.setSessionKey(pkg.sessionKey);
            
            System.out.println("[Client] Successfully obtained service ticket for: " + serviceId);
            System.out.println("[Client] Service ticket valid until: " + new java.util.Date(pkg.expiration));
            
            return serviceTicket;
            
        } catch (Exception e) {
            System.err.println("[Client] Failed to get service ticket: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Step 3: Access application server with service ticket
     */
    private boolean accessApplicationServer(String serviceId, Ticket serviceTicket) {
        System.out.println("\n[Client] Step 2: Accessing application server...");
        
        try {
            // Create authenticator
            Authenticator authenticator = new Authenticator(
                username,
                System.currentTimeMillis()
            );
            
            // Encrypt authenticator with service session key
            byte[] serializedAuth = serializeAuthenticator(authenticator);
            byte[] encryptedAuth = CryptoUtils.encrypt(serializedAuth, serviceTicket.getSessionKey());
            authenticator.setEncryptedData(encryptedAuth);
            
            // Create AP_REQ message
            Message request = Message.createAPRequest(serviceTicket, authenticator);
            
            System.out.println("[Client] Sending AP_REQ to application server...");
            
            // Send request to application server
            Message response = sendToApplicationServer(request);
            
            if (response.getType() == Message.MessageType.ERROR) {
                System.err.println("[Client] ERROR: " + response.getErrorMessage());
                return false;
            }
            
            if (response.getType() != Message.MessageType.AP_REP) {
                System.err.println("[Client] ERROR: Unexpected response type");
                return false;
            }
            
            System.out.println("[Client] Received AP_REP from application server");
            System.out.println("[Client] Authentication confirmed!");
            
            return true;
            
        } catch (Exception e) {
            System.err.println("[Client] Failed to access application server: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Send message to KDC
     */
    private Message sendToKDC(Message message) throws Exception {
        String kdcHost = Config.getKDCHost();
        int kdcPort = Config.getKDCPort();
        
        try (Socket socket = new Socket(kdcHost, kdcPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            
            // Set timeouts
            socket.setSoTimeout(Config.getSocketTimeout());
            
            // Send request
            out.writeObject(message);
            out.flush();
            
            // Receive response
            Message response = (Message) in.readObject();
            return response;
            
        } catch (Exception e) {
            throw new Exception("Failed to communicate with KDC: " + e.getMessage(), e);
        }
    }
    
    /**
     * Send message to application server
     */
    private Message sendToApplicationServer(Message message) throws Exception {
        String appHost = Config.getAppServerHost();
        int appPort = Config.getAppServerPort();
        
        try (Socket socket = new Socket(appHost, appPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            
            // Set timeouts
            socket.setSoTimeout(Config.getSocketTimeout());
            
            // Send request
            out.writeObject(message);
            out.flush();
            
            // Receive response
            Message response = (Message) in.readObject();
            System.out.println(response);
            return response;
            
        } catch (Exception e) {
            throw new Exception("Failed to communicate with application server: " + e.getMessage(), e);
        }
    }
    
    /**
     * Extract session key package from decrypted data
     */
    private SessionKeyPackage extractSessionKeyPackage(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        
        int keyLength = ois.readInt();
        byte[] sessionKey = new byte[keyLength];
        ois.read(sessionKey);
        int nonce = ois.readInt();
        long expiration = ois.readLong();
        
        ois.close();
        return new SessionKeyPackage(sessionKey, nonce, expiration);
    }
    
    /**
     * Serialize authenticator for encryption
     */
    private byte[] serializeAuthenticator(Authenticator authenticator) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(authenticator);
        oos.close();
        return baos.toByteArray();
    }
    
    /* Derive key from password (must match KDC's method) */
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
    
    /* Display current session information */
    private void displaySessionInfo() {
        System.out.println("\n=================================");
        System.out.println("  Session Information");
        System.out.println("=================================");
        System.out.println("User: " + username);
        System.out.println("TGT Status: " + (tgt != null ? "Active" : "Not obtained"));
        
        if (tgt != null) {
            System.out.println("TGT Service: " + tgt.getServiceId());
            System.out.println("TGT Valid Until: " + new java.util.Date(tgt.getExpirationTime()));
            
            long remaining = tgt.getExpirationTime() - System.currentTimeMillis();
            if (remaining > 0) {
                long hours = remaining / (60 * 60 * 1000);
                long minutes = (remaining % (60 * 60 * 1000)) / (60 * 1000);
                System.out.println("Time Remaining: " + hours + "h " + minutes + "m");
            } else {
                System.out.println("Status: EXPIRED");
            }
        }
        
        System.out.println("\nConnected to:");
        System.out.println("  KDC: " + Config.getKDCHost() + ":" + Config.getKDCPort());
        System.out.println("  App Server: " + Config.getAppServerHost() + ":" + Config.getAppServerPort());
        System.out.println("=================================");
    }
    
    /* Inner class to hold session key package data */
    private static class SessionKeyPackage {
        byte[] sessionKey;
        int nonce;
        long expiration;
        
        SessionKeyPackage(byte[] sessionKey, int nonce, long expiration) {
            this.sessionKey = sessionKey;
            this.nonce = nonce;
            this.expiration = expiration;
        }
    }
    
    /* Main method */
    public static void main(String[] args) {
        KerberosClient client = new KerberosClient();
        client.start();
    }
}