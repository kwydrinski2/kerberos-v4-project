package kdc;

import common.Message;
import config.Config;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/*
 * Key Distribution Center (KDC) Main Server
 * Coordinates AS and TGS components and handles client connections
 */
public class KDCMain {
    private Database database;
    private AuthenticationServer authServer;
    private TicketGrantingServer tgsServer;
    private ServerSocket serverSocket;
    private boolean running;
    
    public KDCMain() {
        System.out.println("=================================");
        System.out.println("  Kerberos V4 - KDC Server");
        System.out.println("=================================\n");
        
        // Initialize components
        this.database = new Database();
        this.authServer = new AuthenticationServer(database);
        this.tgsServer = new TicketGrantingServer(database);
        this.running = false;
    }
    
    /* Start the KDC server */
    public void start() {
        try {
            int kdcPort = Config.getKDCPort();
            serverSocket = new ServerSocket(kdcPort);
            running = true;
            
            System.out.println("[KDC] Server started on port " + kdcPort);
            System.out.println("[KDC] Waiting for connections...\n");
            
            // Accept client connections
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("\n[KDC] Client connected: " + 
                        clientSocket.getInetAddress().getHostAddress());
                    
                    // Handle client in new thread
                    Thread clientThread = new Thread(new ClientHandler(clientSocket));
                    clientThread.start();
                    
                } catch (IOException e) {
                    if (running) {
                        System.err.println("[KDC] Error accepting connection: " + e.getMessage());
                    }
                }
            }
            
        } catch (IOException e) {
            System.err.println("[KDC] Failed to start server: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /* Stop the KDC server */
    public void stop() {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            System.out.println("\n[KDC] Server stopped");
        } catch (IOException e) {
            System.err.println("[KDC] Error stopping server: " + e.getMessage());
        }
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
                Message response;
                
                // Route request to appropriate server component
                switch (request.getType()) {
                    case AS_REQ:
                        System.out.println("[KDC] Routing to Authentication Server");
                        response = authServer.handleAuthenticationRequest(request);
                        break;
                        
                    case TGS_REQ:
                        System.out.println("[KDC] Routing to Ticket Granting Server");
                        response = tgsServer.handleTicketRequest(request);
                        break;
                        
                    default:
                        System.out.println("[KDC] ERROR: Unknown message type: " + request.getType());
                        response = Message.createErrorMessage("Unknown message type");
                        break;
                }
                
                // Send response back to client
                out.writeObject(response);
                out.flush();
                
                System.out.println("[KDC] Response sent to client");
                System.out.println("[KDC] Connection closed\n");
                
            } catch (Exception e) {
                System.err.println("[KDC] Error handling client: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println("[KDC] Error closing socket: " + e.getMessage());
                }
            }
        }
    }
    
    /* Main method */
    public static void main(String[] args) {
        KDCMain kdc = new KDCMain();
        
        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[KDC] Shutting down...");
            kdc.stop();
        }));
        
        kdc.start();     // Start the server

    }
}