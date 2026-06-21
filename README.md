

### Description: 
A nodeJS based utility to mimic lock and App.
Lock is simulated by device.js
App is simulated by app.js

### For more details with images refer to the PDF file in the repo!


## Folder Structure:
Once installed at your end successfully, you should see the following folder structure:
![[Pasted image 20260621171058.png]]
#### AllCerts:
AllCerts folder contain **all** the certificates required. So it contains root, intermediate and device certificates. The broker side certificates are not required. We only use the device side of the certificate chain.
**This folder is not being used currently. It's only there for reference and any cross checking that one may need to do.**

#### appCerts:
All the certificates required by the app.
And app just requires the root certificate (root public certificate).
==This is the emulation of the certificates that the mobile app will have==

#### devCerts:
All the certificates required required by the lock.
So it contains device and the intermediate certificate. These will be sent by the lock to the app and app will authenticate it against the root certificate.
==This is the emulation of the certificates that the Lock will have==

#### data:
data folder will be populated by device.js and app.js with `packet_dev.txt` and `packet_app.txt` respectively.
Since this PoC is for proving the encryption decryption mechanism and not the transport mechanism, the data sent from lock to app is stored in `packet_dev.txt` and data sent for app to lock is stored in  `packet_app.txt`

### device.js and app.js:
device.js is executed by calling `node .\device.js`
app.js is executed by calling `node .\app.js`

**`device.js` runs in two stages:**
First step it executes Step 2 (refer table **Secure Device On-boarding Concept** at bottom) 
In this step it writes to  `packet_dev.txt`
Then the user is expected to run `app.js`. (This executes )
Then in the second steps 3 and 4 from the below table.
Then device.js is allowed to continue further where it executes step 5 from the table.


> [!NOTE]  
> Make sure to run device.js and app.js in different terminals.


## Procedure:
#### Step 1:
**Terminal 1:**
![[Pasted image 20260621174826.png]]
Press Enter
![[Pasted image 20260621174943.png]]

#### Step 2:
**Terminal 2:**
![[Pasted image 20260621175216.png]]
![[Pasted image 20260621175243.png]]

#### Step 3:
**Terminal 1:**
Press **Enter** on `Do you want to run the xtract part?`:
![[Pasted image 20260621175520.png]]



For trials with different ssid and passwords, you can edit the ssid and password in `app.js`:
![[Pasted image 20260621175701.png]]




### Table:

|                                       |                                                                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Secure Device On-boarding Concept** |                                                                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **Implementation Logic**              |                                                                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **Sr.no**                             | **Action**                                                        | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 1                                     | Initiation                                                        | - User puts the device in AP mode using sequence of keys.  <br>- User scans the QR Code using mobile APP.  <br>- Mobile app **Only** gets the Device ID.  <br>- Using internal formulations mobile App derives the SSID and Password.  <br>- Now Mobile app sends connection request to the device.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 2                                     | Ephemeral Key Generation and Sharing (Device Side Implementation) | - The device generates the **Device Ephemeral Private Key** (DEPtK) and **Device Ephemeral Public key**(DEPlK) (`mbedtls_ecdh_gen_public()`?)  <br>- Device generates a **nonce** (DN). A nonce is a 128 bit or 256 bit random number generated fresh for each new provisioning session.  <br>- A Device Hash (DH) is computed using Device ID, DEPlK and DN.  <br>- The DH is signed using **Device Private Key** (DPK) to create **Device Signature**(DS).  <br>DH = SHA256(DeviceID \| DEPlK \| DN)  <br>- Now the device sends the following to the mobile:  <br>a. DEPlK.  <br>b. DS  <br>c. **Device Public Certificate** (DPC)  <br>d. Intermediate Device Certificate (IDC)  <br>e. DN                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 3                                     | Authentication of the DEPlK at Mobile app                         | - Certificate chain verification: If certification chain is verified only then we move to the next steps.  <br>- Using Device Nonce, Device ID (the app has it because it has scanned the QR code), and DEPlk, the app creates **local hash** (LH).  <br>(LH = SHA256(DeviceID \| DEPlK \| DeviceNonce))  <br>- Get the **Device public key** (DPlK) from DPC.  <br>- Verify the DS. (ECDSA_Verify(DPlK,DS,LH))  <br>- If the verification succeeds it means that "**_DEPlK is authentic!_**"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 4                                     | Shared Symmetric AES Key                                          | - Now the app generates it's ephemeral key pair. (AEPtK, AEPlK)  <br>- ECDH is run on AEPtK + DEPlK to generate what can be called as a "shared secret".  <br>- This shared secret is run through KDF to generate **Shared Symmetric AES Key** (SSAK). Pass the Device Nonce and purpose of key generation to ensure uniqueness. (SSAK = HKDF-SHA256(  <br>        SharedSecret,  <br>        salt = DeviceNonce,  <br>        info = "WiFiProvisioning"  <br>))  <br>- The app collects the Wifi Credentials from the user.  <br>- Generate a 12 byte nonce. We can call it as **AppNonce** (AN). Simply a 96 bit random number.  <br>-  For more secure encryption adding Time stamp, Device ID and DeviceNonce is recommended. (This is called as **Additional Authenticated Data**)  <br>- This generates **cipher text** (CT) and **Authentication Tag**(Tag).  <br>- App creates a packet which consists of following:  <br>AEPlK      : 65 bytes (P-256 uncompressed)  <br>AppNonce   : 12 bytes (AES-GCM IV)  <br>AAD        : variable  <br>Ciphertext : variable  <br>Tag        : 16 bytes (AES-GCM Authentication Tag)  <br>This packet is now sent to the device. |
| 5                                     | Data Extraction at Device Level                                   | - AES key generation at Device using AEPlK and DEPtK. For this run ECDH on DEPtK + AEPlK → Shared Secret, then KDF(Shared Secret) → SSAK→ Verify Tag→ Decrypt Wifi Credentials.  <br>1. ECDH(DEPtK, AEPlK) → Shared Secret  <br>2. HKDF(Shared Secret, DN, "WiFiProvisioning") → SSAK  <br>3. Verify AES-GCM Authentication Tag  <br>4. If verification succeeds:  <br>      Decrypt and store WiFi credentials  <br>   Else:  <br>      Reject provisioning request                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 6                                     | Note                                                              | For KDF use HKDF-SHA256 and for encryption use AES-256-GCM                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
