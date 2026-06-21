const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');


const cstrGreenStart = "\x1b[32m";
const cstrBlueStart = "\x1b[34m";
const cstrRedStart = "\x1b[31m";
const cstrSplStringEnd = "\x1b[0m";

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
const certPath = path.join(__dirname, 'devCerts');
const intmdtCertPath = path.join(certPath, 'intermediate.crt');
const deviceCertPath = path.join(certPath, 'device.crt');





console.log("Starting the Device.js application...");

const [,, ...args] = process.argv;
console.log("First Argument:", args[0]);

let privateKey, publicKey;
let DeviceEphemeralKey = {privateKey, publicKey};
let DeviceNonce = null;
let DeviceHash = null;
let DeviceSignature = null;
let DeviceID = "LOCK12345"; //Assumed device id for demo.
let DeviceSharedSecret = null;
let packetApp = null;
let DeviceSSK = null; // Shared Secret Symmetric Key derived from the shared secret, used for encrypting credentials.


function runInit() {
    console.log(cstrGreenStart + "Step 1: Generating a new ephemeral key pair..." + cstrSplStringEnd);
    generateEphemeralKey();
    console.log(cstrGreenStart + "Step 2: Generate 128 bit Device nonce..." + cstrSplStringEnd);
    generateNonce();
    console.log(cstrGreenStart + "Step 3: Skipped" + cstrSplStringEnd);
    console.log(cstrGreenStart + "Step 4: Generate Device Signature..." + cstrSplStringEnd);
    generateSignatureV2();
    console.log(cstrGreenStart + "Step 5: Create and send Package to the App..." + cstrSplStringEnd);
    sendPackageToApp();
}

function runXtract() {
    console.log(cstrGreenStart + "Step 1: Read Package from App..." + cstrSplStringEnd);
    readPackageFromApp();
    console.log("Step 1: Compute Shared Secret...");
    computeSharedSecret();
    console.log("Step 2: Generate Shared Secret Symmetric Key...");
    computeSharedSecretSymmetricKey();
    console.log("Step 3: Verify Tag and Decrypt Credentials...");
    verifyTagAndDecryptCredentials();
}

async function promptForXtract() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    return new Promise((resolve) => {
        rl.question("Do you want to run the xtract part? (Press Enter to continue, type 'no' to skip): ", (answer) => {
            rl.close();
            if (answer.toLowerCase() !== 'no') {
                runXtract();
            }
            resolve();
        });
    });
}

async function main() {
    // Run init by default
    runInit();
    
    // If no argument or 'init' was passed, prompt for xtract
    if (!args[0] || args[0] === 'init') {
        await promptForXtract();
    } else if (args[0] === 'xtract') {
        runXtract();
        console.log(cstrGreenStart + "For Verification only!!" + cstrSplStringEnd);
        console.log("Device Shared Secret", DeviceSharedSecret.toString('hex'));
        console.log("Device Nonce", DeviceNonce.toString('hex'));
        console.log("Device Symmetric Key", DeviceSSK.toString('hex'));
    }
}

main();



function generateEphemeralKey(){
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    DeviceEphemeralKey.privateKey = ecdh.getPrivateKey();   
    console.log(DeviceEphemeralKey.privateKey.constructor.name);
    DeviceEphemeralKey.publicKey = ecdh.getPublicKey();
    console.log(cstrBlueStart + "Generated Device Ephemeral Public Key:", DeviceEphemeralKey.publicKey.toString('hex')  +  cstrSplStringEnd);    
    console.log(cstrBlueStart + "Generated Device Ephemeral Private Key:", DeviceEphemeralKey.privateKey.toString('hex') + cstrSplStringEnd );  
}

function generateNonce() {
    
    DeviceNonce = crypto.randomBytes(16); // 128-bit nonce
    console.log(DeviceNonce.constructor.name);
    console.log(cstrBlueStart + "Generated Device Nonce:", DeviceNonce.toString('hex') + cstrSplStringEnd);
}
/*
function computeHash() {//Probably not required any more as we can directly sign the data without hashing it separately. But keeping it for now.
    // Implement hash computation logic here
    DeviceHash = crypto.createHash('sha256').update(DeviceID).update(DeviceEphemeralKey.publicKey).update(DeviceNonce).digest();
    console.log(DeviceHash.constructor.name);
    console.log(cstrBlueStart + "Computed Device Hash:", DeviceHash.toString('hex') + cstrSplStringEnd);
} 
*/  

function generateSignature() {//Probably not required any more as we can directly sign the data without hashing it separately. But keeping it for now.
    // Implement signature generation logic here
    const devicePrivateKey = fs.readFileSync(
        'E:/certs/device.key',
        'utf8'
    );
    DeviceSignature = crypto.sign(
        null,
        DeviceHash,
        devicePrivateKey
    );
    console.log(cstrBlueStart + "Generated Device Signature:", DeviceSignature.toString('hex') + cstrSplStringEnd);
}

function generateSignatureV2() {
    const devicePrivateKey = fs.readFileSync(
        'E:/certs/device.key',
        'utf8'
    );

    DeviceSignature = crypto.createSign('SHA256');

    DeviceSignature.update(DeviceID);
    DeviceSignature.update(DeviceEphemeralKey.publicKey);
    DeviceSignature.update(DeviceNonce);
    DeviceSignature.end();
    DeviceSignature = DeviceSignature.sign(devicePrivateKey);



    console.log(cstrBlueStart + "Generated Device Signature:", DeviceSignature.toString('base64') + cstrSplStringEnd);
}


function sendPackageToApp() {
    // Implement package sending logic here
    const packet = {
        DEPlK: DeviceEphemeralKey.publicKey.toString('hex'),
        DS: DeviceSignature.toString('base64'),
        DPC: fs.readFileSync(deviceCertPath, 'utf8'),
        IDC: fs.readFileSync(intmdtCertPath, 'utf8'),
        DN: DeviceNonce.toString('hex')
    };
    const packetJson = JSON.stringify(packet, null, 2);

      try {
        fs.writeFileSync(
            filePathDev,
            packetJson,
            'utf8'
        );

        console.log(
            cstrGreenStart +
            'Packet written to ' + filePathDev +
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

// xtract functions below


function readPackageFromApp(){
         try {
            const packetAppJson = fs.readFileSync(
                filePathApp,
                'utf8'
            );
    
            packetApp = JSON.parse(packetAppJson);
            console.log(cstrBlueStart + 'Packet received successfully.' + cstrSplStringEnd);
            console.log(packetApp);
        }
        catch (err) {
            console.error(
                cstrRedStart + 'Failed to read packet:' + cstrSplStringEnd,
                err.message
            );
        }
}

function computeSharedSecret() {
    const ecdh = crypto.createECDH('prime256v1');
    console.log(cstrBlueStart + "Device Ephemeral Pvt Key: " + cstrSplStringEnd + DeviceEphemeralKey.privateKey.toString('hex'));
    ecdh.setPrivateKey(DeviceEphemeralKey.privateKey);
    DeviceSharedSecret = ecdh.computeSecret(Buffer.from(packetApp.AEPlK, 'hex'));
    console.log(cstrBlueStart + "Computed Shared Secret:", DeviceSharedSecret.toString('hex') + cstrSplStringEnd);
}

function computeSharedSecretSymmetricKey() {
 DeviceSSK = Buffer.from(crypto.hkdfSync(
        'sha256',
        DeviceSharedSecret,                 // Input Key Material (IKM)
        DeviceNonce,                        // Salt (Buffer)
        'WifiProvisioning',                 // Info
        32                                 // Output length in bytes
    ));

    //console.log(DeviceSSK.constructor.name);
    console.log(
        
        cstrBlueStart +
        "Computed Shared Secret Symmetric Key: " +
        DeviceSSK.toString('hex') +
        cstrSplStringEnd
    );


}

function verifyTagAndDecryptCredentials() {
    try {

        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            DeviceSSK,
            Buffer.from(packetApp.IV, 'hex')
        );

        //
        // Set AAD
        //
        decipher.setAAD(
            Buffer.from(packetApp.AAD, 'hex')
        );

        //
        // Set Authentication Tag
        //
        decipher.setAuthTag(
            Buffer.from(packetApp.TAG, 'hex')
        );

        //
        // Decrypt
        //
        const decryptedBuffer = Buffer.concat([
            decipher.update(
                Buffer.from(packetApp.CT, 'hex')
            ),
            decipher.final()
        ]);

        console.log(
            cstrGreenStart +
            "Authentication Tag Verified Successfully." +
            cstrSplStringEnd
        );

        console.log(
            cstrBlueStart +
            "Decrypted Credentials JSON: " +
            decryptedBuffer.toString('utf8') +
            cstrSplStringEnd
        );

        const wifiCredentials =
            JSON.parse(
                decryptedBuffer.toString('utf8')
            );

        console.log(
            cstrGreenStart +
            "SSID: " +
            wifiCredentials.ssid +
            cstrSplStringEnd
        );

        console.log(
            cstrGreenStart +
            "Password: " +
            wifiCredentials.password +
            cstrSplStringEnd
        );

        return wifiCredentials;
    }
    catch (err) {

        console.error(
            cstrRedStart +
            "Authentication Tag Verification Failed." +
            cstrSplStringEnd
        );

        console.error(
            cstrRedStart +
            err.message +
            cstrSplStringEnd
        );

        return null;
    }
}