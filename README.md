# CSCE377 - Fall 2025 #
# Kerberos V4 Project #

## Step 1: Compile the Project

### Option A: Manual Compilation (Command Line)

javac -d bin -sourcepath src src/config/*.java src/common/*.java src/kdc/*.java src/server/*.java src/client/*.java

## Step 2: Run the Components

### Terminal 1: Start the KDC Server

cd Kerberos-V4-Project
java -cp bin kdc.KDCMain

**Expected Output:**

=================================
  Kerberos V4 - KDC Server
=================================

[Database] Added user: alice
[Database] Added user: bob
[Database] Added user: charlie
[Database] Added service: tgs
[Database] Added service: fileserver
[Database] Initialized with default users and services
[AS] Authentication Server initialized
[TGS] Ticket Granting Server initialized
[KDC] Server started on port 8888
[KDC] Waiting for connections...

**Leave this terminal running**

### Terminal 2: Start the Application Server

cd Kerberos-V4-Project
java -cp bin server.ApplicationServer

**Expected Output:**

[AppServer] Retrieve key from KDC
[AppServer] Generated key for service: fileserver
[AppServer] Key: [B@17f052a3
=================================
  Kerberos V4 - Application Server
  Service: fileserver
=================================

[AppServer] Server started on port 9999
[AppServer] Service ID: fileserver
[AppServer] Waiting for connections...

**Leave this terminal running**

### Terminal 3: Run the Client

cd Kerberos-V4-Project
java -cp bin client.KerberosClient


**Expected Output:**

=================================
  Kerberos V4 - Client
=================================

=== User Login ===
Username: 


## Step 3: Test the System

### Login with Test Users

Use one of these credential pairs:

| Username | Password     |
|----------|--------------|
| alice    | password123  |
| bob      | password456  |
| charlie  | password789  |
