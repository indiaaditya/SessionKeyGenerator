const crypto = require('crypto');
const fs = require('fs');
const path = require('path');


const cstrGreenStart = "\x1b[32m";
const cstrBlueStart = "\x1b[34m";
const cstrSplStringEnd = "\x1b[0m";
const cstrRedStart = "\x1b[31m";

//relative path for the data files: Device
const dirPath = path.join(__dirname, 'data');
const filePathDev = path.join(dirPath, 'packet_dev.txt');
if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
}
//relative path for the data files: app
const filePathApp = path.join(dirPath, 'packet_app.txt');
if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
}
//relative path for the data files: certificates
const certPath = path.join(__dirname, 'appCerts');
const rootCertPath = path.join(certPath, 'root.crt');


let privateKey, publicKey;
let AppEphemeralKey = {privateKey, publicKey};
var AppECDH;
var rootCert = null, intermediateCert = null, deviceCert = null;
var devicePublicKey = null;
let AppNonce = null;
var sharedSecret = null;
var sharedSymmetricAESKey = null;
var sharedSymmetricAESKeyBuffer = null;
var sharedSymmetricAESKeyString = null;
var wifiCredentials =
{
    ssid: 'MyHome2',
    password: 'abc123789'
};


var packet = {
    DEPlK: '',
    DS: '',
    DPC: '',
    IDC: '',
    DN: '',
};

var aad =
{
    DeviceID: null,
    DN: null,
    Timestamp: null
};
var aadBuffer = null;

let QR_code = "LOCK12345"; //Assumed device id for demo.

console.log("Starting the App.js application...");

console.log(cstrGreenStart + "Step 1: Read the Package from the Device..." + cstrSplStringEnd);
readPackageFromDevice();
console.log(cstrGreenStart + "Step 2: verify certification chain..." + cstrSplStringEnd);
if (verifyCertificateChain() == true) {
    console.log(cstrGreenStart + "Step 3: Extract Device Public Key from Device Public Certificate..." + cstrSplStringEnd);
    devicePublicKey = extractDevicePublicKey();
    console.log(cstrGreenStart + "Step 4: Validate QR code and Device ID"  + cstrSplStringEnd);//"Step 4: Create Local hash..."
    if (validateQRCodeAndDeviceID() == true) {
        //computeHash();//Not required any more as we can directly sign the data without hashing it separately. But keeping it for now.
        console.log(cstrGreenStart + "Step 5: Verify Device Signature..." + cstrSplStringEnd);
        if (verifyDeviceSignature() == true) {
            console.log(cstrGreenStart + "Step 6: Generate App's Ephemeral Key pair..." + cstrSplStringEnd);
            generateEphemeralKey();
            console.log(cstrGreenStart + "Step 7: Generate shared secret..." + cstrSplStringEnd);
            generateSharedSecret();
            console.log(cstrGreenStart + "Step 8: Generate shared symmetric AES Key..." + cstrSplStringEnd);
            generateSharedSymmetricAESKey();
            console.log(cstrGreenStart + "Step 9: Get SSID and Password from the user..." + cstrSplStringEnd);
            console.log(cstrBlueStart + "Hard coded right now:", JSON.stringify(wifiCredentials)  +  cstrSplStringEnd);    
            console.log(cstrGreenStart + "Step 10: Generate App Nonce..." + cstrSplStringEnd);
            generateNonce();
            console.log(cstrGreenStart + "Step 11: Generate Cipher Text and Authentication Tag with Additional Authentic Data..." + cstrSplStringEnd);
            fill_AAD_buffer();
            generateCipherTextAndAuthTag();
            console.log(cstrGreenStart + "Step 12: Send package to device..." + cstrSplStringEnd);
            sendPackageToApp();


        }
    }
}

function generateEphemeralKey(){
    AppECDH = crypto.createECDH('prime256v1');
    AppECDH.generateKeys();
    AppEphemeralKey.privateKey = AppECDH.getPrivateKey();   
    AppEphemeralKey.publicKey = AppECDH.getPublicKey();
    console.log(cstrBlueStart + "Generated App Ephemeral Public Key:", AppEphemeralKey.publicKey.toString('hex')  +  cstrSplStringEnd);    
    console.log(cstrBlueStart + "Generated App Ephemeral Private Key:", AppEphemeralKey.privateKey.toString('hex') + cstrSplStringEnd );  

}

function generateNonce() {    
    AppNonce = crypto.randomBytes(16); // 128-bit nonce
    console.log(cstrBlueStart + "Generated App Nonce:", AppNonce.toString('hex') + cstrSplStringEnd);
}   

function readPackageFromDevice() {
     try {
        const packetJson = fs.readFileSync(
            filePathDev,
            'utf8'
        );

        packet = JSON.parse(packetJson);
        console.log(cstrBlueStart + 'Packet received successfully.' + cstrSplStringEnd);
        console.log(packet);
    }
    catch (err) {
        console.error(
            cstrRedStart + 'Failed to read packet:' + cstrSplStringEnd,
            err.message
        );
    }
}

function verifyCertificateChain() {
    const rootPem = fs.readFileSync(
        rootCertPath,
        'utf8'
    );
    rootCert = new crypto.X509Certificate(rootPem);
    console.log(cstrBlueStart + 'Root certificate loaded successfully.' + cstrSplStringEnd);

    //verify intermediate certificate
    intermediateCert = new crypto.X509Certificate(packet.IDC);
    const validIDC = intermediateCert.verify(rootCert.publicKey);

    if (validIDC == true) {
        console.log(cstrBlueStart + 'IDC valid:' + cstrSplStringEnd, validIDC);
        //verify device certificate
        deviceCert = new crypto.X509Certificate(packet.DPC);
        const validDPC = deviceCert.verify(intermediateCert.publicKey);
        if (validDPC == true){
            console.log(cstrBlueStart + 'DPC valid:' + cstrSplStringEnd, validDPC);
        return true;
        }
    else
        {
            console.log(cstrRedStart + 'DPC valid:' + cstrSplStringEnd, validDPC);
            return false;
        }

    }
    else {
        console.log(cstrRedStart + 'IDC valid:' + cstrSplStringEnd, validIDC);
        return false;
    }
}

function extractDevicePublicKey() {
    const dpk = deviceCert.publicKey;
    console.log(cstrBlueStart + "Extracted Device Public Key:", dpk.export({ type: 'spki', format: 'pem' }) + cstrSplStringEnd);
    return dpk;
}

function validateQRCodeAndDeviceID() {
    // Implement QR code and Device ID validation logic here
    const match =
    deviceCert.subject.match(
        /CN=([^,\n]+)/i
    );
    const Certificate_DeviceID =
    match ? match[1] : null;
    if (QR_code !== Certificate_DeviceID) {
        console.log(cstrRedStart + "QR code Device ID does not match certificate Device ID." + cstrSplStringEnd);
        return false;
    }
    else {
        console.log(cstrBlueStart + "QR code Device ID matches certificate Device ID." + cstrSplStringEnd);
        return true;
    }   
}

function verifyDeviceSignature() {
    // console.log("Hash:" + DeviceHash.toString('hex'));
    // console.log("DPK:" + devicePublicKey.export({ type: 'spki', format: 'pem' }));
    // console.log("DS:" + packet.DS);

    const verify = crypto.createVerify('SHA256');
    verify.update(QR_code);
    verify.update(
        Buffer.from(packet.DEPlK, 'hex')
    );
    verify.update(
        Buffer.from(packet.DN, 'hex')
    );
    const isValidSignature =
    verify.verify(
        devicePublicKey,
        Buffer.from(packet.DS, 'base64')
    );

    let clrStart;
    if(isValidSignature == true) {
        clrStart = cstrBlueStart;
        return true;
    }
    else{
        clrStart = cstrRedStart;   
        return false;
    }
    console.log(clrStart + "Device signature is valid:" + cstrSplStringEnd, isValidSignature);
}


function generateSharedSecret() {
    //Extract Device Public Ephemeral Key from the package
    const devicePublicEphemeralKey = Buffer.from(packet.DEPlK, 'hex');  
    sharedSecret = AppECDH.computeSecret(devicePublicEphemeralKey);
    console.log(cstrBlueStart + "Shared Secret:" + cstrSplStringEnd, sharedSecret.toString('hex'));
}

function generateSharedSymmetricAESKey() {
  
 sharedSymmetricAESKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.from(packet.DN, 'hex'), 'WifiProvisioning', 32); // Derive a 256-bit AES key 
 sharedSymmetricAESKeyBuffer = Buffer.from(sharedSymmetricAESKey);
//sharedSymmetricAESKeyString = sharedSymmetricAESKeyBuffer.toString('base64');
 console.log(cstrBlueStart + "sharedSymmetricAESKey:" + sharedSymmetricAESKeyBuffer.toString('hex') + cstrSplStringEnd);
  //console.log(cstrBlueStart + "sharedSymmetricAESKey:" + JSON.stringify(sharedSymmetricAESKey) + cstrSplStringEnd);
}

function fill_AAD_buffer() {    
    aad.DeviceID = QR_code;
    aad.DN = packet.DN;
    aad.Timestamp = Date.now().toString();
    aadBuffer = Buffer.from(JSON.stringify(aad));
    console.log(cstrBlueStart + "AAD buffer:" + JSON.stringify(aad) + cstrSplStringEnd);    
    console.log(cstrBlueStart + "AAD buffer length:" + aadBuffer.length + cstrSplStringEnd);
    //console.log(cstrBlueStart + "AAD buffer:" + JSON.stringify(aad) + cstrSplStringEnd);    
}

function generateCipherTextAndAuthTag() {
    // Implement encryption logic here using sharedSymmetricAESKey, AppNonce and wifiCredentials
    // Use AES-GCM mode for encryption to get both cipher text and authentication tag

    const cipher =
        crypto.createCipheriv(
            'aes-256-gcm',
            sharedSymmetricAESKeyBuffer,
            AppNonce
        );

    cipher.setAAD(
        aadBuffer
    );

    const lclBuffer = Buffer.from(JSON.stringify(wifiCredentials),'utf8'); 

    CipherText =
        Buffer.concat([
            cipher.update(lclBuffer),
            cipher.final()
        ]);
    AuthenticationTag = cipher.getAuthTag();
    console.log(cstrBlueStart + "CipherText:" + CipherText.toString('hex') + cstrSplStringEnd);    
    console.log(cstrBlueStart + "Tag:" + AuthenticationTag.toString('hex') + cstrSplStringEnd);    
}


function sendPackageToApp() {
    // Implement package sending logic here
    const packet = {
        AEPlK: AppEphemeralKey.publicKey.toString('hex'),
        IV: AppNonce.toString('hex'),
        AAD: aadBuffer.toString('hex'), 
        CT: CipherText.toString('hex'),
        TAG: AuthenticationTag.toString('hex')
    };
    const packetJson = JSON.stringify(packet, null, 2);

      try {
        fs.writeFileSync(
            filePathApp,
            packetJson,
            'utf8'
        );

        console.log(
            cstrGreenStart +
            'Packet written to packet_app.txt' +
            cstrSplStringEnd
        );
    }
    catch (err) {
        console.error(
            cstrRedStart +
            'Failed to write packet file: ' +
            err.message +
            cstrSplStringEnd
        );
    }


    console.log(cstrBlueStart + "Sending Package to App:", packetJson + cstrSplStringEnd);
}

