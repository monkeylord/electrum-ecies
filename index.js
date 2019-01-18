'use strict';

var bsv = require('bsv');
var PrivateKey = bsv.PrivateKey;
var PublicKey = bsv.PublicKey;
var Hash = bsv.crypto.Hash;
var crypto = require('crypto');

function Electrum_ecdh_key(publicKey,privateKey){
    //Get ECDH Key
    var buf = PublicKey(publicKey.point.mul(privateKey.bn)).toBuffer();
    return Hash.sha512(buf);
}

function encrypt(plainText,publicKey,privateKey=null){
    //Prepare keys
    var recv_pubkey = new PublicKey(publicKey);
    //Override ephemeral_key if privateKey is given. This overriding is for traditional ECIES.
    var ephemeral_key = new PrivateKey(privateKey);
    var ecdh_key = Electrum_ecdh_key(recv_pubkey,ephemeral_key);
    var iv=ecdh_key.subarray(0,16);
    var key_e=ecdh_key.subarray(16,32);
    var key_m=ecdh_key.subarray(32,64);
    
    //Encrypt with AES-128-CBC
    var cipher = crypto.createCipheriv('aes-128-cbc', key_e, iv);
    var crypted = cipher.update(plainText, 'utf8', 'binary');
    crypted += cipher.final('binary');
    crypted = new Buffer(crypted, 'binary');
    
    //Build Encrypted Massage
    var ephemeral_pubkey = ephemeral_key.toPublicKey().toBuffer();
    var encrypted=Buffer.concat([new Buffer('BIE1') , ephemeral_pubkey , crypted]);
    var hmac = Hash.sha256hmac(new Buffer(encrypted),new Buffer(key_m))
    
    return Buffer.concat([encrypted,hmac]).toString('base64');
}

function decrypt(encryptedMsg,privateKey,publicKey=null){
    //Read from Encrypted Massage
    var encrypted=Buffer.from(encryptedMsg,'base64');
    var magic=encrypted.subarray(0,4);
    //Override publicKey in message when publicKey is given. The overriding is for sender to retrieve message he sent in traditional ECIES.
    var ephemeral_pubkey=(publicKey==null)?PublicKey.fromBuffer(encrypted.subarray(4,37)):new PublicKey(publicKey);
    var ciphertext = encrypted.subarray(37,encrypted.length-32);
    var mac= encrypted.subarray(encrypted.length-32);
    
    //Prepare Keys
    var recv_prvKey = new PrivateKey(privateKey);
    var ecdh_key = Electrum_ecdh_key(ephemeral_pubkey,recv_prvKey);
    var iv=ecdh_key.subarray(0,16);
    var key_e=ecdh_key.subarray(16,32);
    var key_m=ecdh_key.subarray(32,64);
    
    //Check HMAC
    var crypted=encrypted.subarray(0,encrypted.length-32);
    var hmac = Hash.sha256hmac(new Buffer(crypted),new Buffer(key_m));
    if(hmac.compare(mac)!=0)console.log("HMAC Error: "+encryptedMsg);
    
    //Decrypt with AES-128-CBC
    var decipher = crypto.createDecipheriv('aes-128-cbc', key_e, iv);
    var decrypted= decipher.update(ciphertext.toString('binary'),'binary', 'utf8');
    decrypted += decipher.final('utf8');
    decrypted = new Buffer(decrypted, 'binary');
    
    return decrypted;
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  ecdh_key: Electrum_ecdh_key,
}