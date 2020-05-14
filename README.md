# Electrum ECIES

> This repo is depreciated, as the project is merged into [bsv library](https://github.com/moneybutton/bsv).
>
> You can view new [usage](https://github.com/moneybutton/bsv/blob/master/docs/ecies.md) with bsv library.

Electrum ECIES js implement, encrypt/decrypt message in BIE1 format, like Electrum/Electron Tools -> Encrypt/decrypt message.

You can encrypt message just with receiver's publickey, and receiver can decrypt message with his privatekey.

### Usage

Encrypt a message, so it can be decrypted in Electrum/Electron Cash Wallet.

Or decrypt message Electrum/Electron Cash Wallet encrypted.

#### Install via NPM

~~~shell
npm install electrum-ecies
~~~

#### In browser

~~~javascript
<script src='https://unpkg.com/bsv'></script>
<script src='https://unpkg.com/electrum-ecies'></script>
~~~

### Examples

#### Encrypt Message with Receiver's PublicKey

~~~javascript
const ECIES = require('electrum-ecies');

//Receiver's PublicKey: 02c01c35eef31acb60386f7fb8e0267f08faf5724d1b2fa1f3588a5fef3e726309

ECIES.encrypt('Hello','02c01c35eef31acb60386f7fb8e0267f08faf5724d1b2fa1f3588a5fef3e726309'); 

//'QklFMQMFmPdvjFe8Wfo+JWmTpo+33LXc+4G8ThfaucU72kieb6lWEv4layTb0x5tzpi6lA2it8rO/ELrXomJqC53uBOd+DZSzDhCSpK6SwR+Itt+Pw=='

//BIE1 use ephemeral keys, so ciphertext is different every time.
~~~

#### Decrypt BIE1 Message with Receiver's PrivateKey

~~~javascript
const ECIES = require('electrum-ecies');

//Receiver's PrivateKey:a1b50c4d420b20059b01e7eea3b3d8a5e943728dfedf962628ca18d04bfa2cfc

//Decrypt Above Message

ECIES.decrypt('QklFMQMFmPdvjFe8Wfo+JWmTpo+33LXc+4G8ThfaucU72kieb6lWEv4layTb0x5tzpi6lA2it8rO/ELrXomJqC53uBOd+DZSzDhCSpK6SwR+Itt+Pw==','a1b50c4d420b20059b01e7eea3b3d8a5e943728dfedf962628ca18d04bfa2cfc')

//<Buffer 68 65 6c 6c 6f>
~~~

#### I Just Want the ECDH Key

~~~javascript
const ECIES = require('electrum-ecies');

const PublicKey = require('bsv').PublicKey;

const PrivateKey = require('bsv').PrivateKey;

var ecdh_key = ECIES.ecdh_key(new PublicKey([Receiver Pubkey]),new PrivateKey([Sender/Ephemeral PrivKey]))

var iv=ecdh_key.subarray(0,16);

var key_aes=ecdh_key.subarray(16,32);

var key_hmac=ecdh_key.subarray(32,64);
~~~

#### Traditional 2 keys ECIES

~~~js
const ECIES = require('electrum-ecies');
//Receiver Private Key:3876fd62a094f0700077c52f3e95cf776c1d3bc26937ed9a8c7da316b4486d2a
//Receiver Public Key:03e7f56e86cab54141d4cd1c49c79cdd31803ddb25aa1e2e37692c54f592e432c7
//Sender Private Key:da25c51abb3ef47d496caf4b857d9490949d926ba449de3b8e68417eecc71bf9
//Sender Public Key:0343ea04cfc5df7b486f4e37583fe43f553bd8d50c0a3ba8cd046c628de94828fd


//Encrypt with Receiver PublicKey and Sender PrivateKey
ECIES.encrypt('Hi ECIES','03e7f56e86cab54141d4cd1c49c79cdd31803ddb25aa1e2e37692c54f592e432c7','da25c51abb3ef47d496caf4b857d9490949d926ba449de3b8e68417eecc71bf9')
//'QklFMQND6gTPxd97SG9ON1g/5D9VO9jVDAo7qM0EbGKN6Ugo/RA+JiiLFOL59qviXS+MB87SL2x2pDfJr7vUttchThLokqLeeUKphuvGI+iLQ2Eulg=='

//Decrypt with Receiver PrivateKey
ECIES.decrypt('QklFMQND6gTPxd97SG9ON1g/5D9VO9jVDAo7qM0EbGKN6Ugo/RA+JiiLFOL59qviXS+MB87SL2x2pDfJr7vUttchThLokqLeeUKphuvGI+iLQ2Eulg==','3876fd62a094f0700077c52f3e95cf776c1d3bc26937ed9a8c7da316b4486d2a')
//<Buffer 48 69 20 45 43 49 45 53>

//Decrypt with Receiver PublicKey and Sender PrivateKey (if sender want to retrieve message in this case)
ECIES.decrypt('QklFMQND6gTPxd97SG9ON1g/5D9VO9jVDAo7qM0EbGKN6Ugo/RA+JiiLFOL59qviXS+MB87SL2x2pDfJr7vUttchThLokqLeeUKphuvGI+iLQ2Eulg==','da25c51abb3ef47d496caf4b857d9490949d926ba449de3b8e68417eecc71bf9','03e7f56e86cab54141d4cd1c49c79cdd31803ddb25aa1e2e37692c54f592e432c7')
//<Buffer 48 69 20 45 43 49 45 53>

//Note: By default, ECIES encrypt with random ephemeral private key which can't be retrieved later. We overrided ephemeral key with given private key here.
~~~

### Donation

If you like it.

BSV address: 1BHcPbcjRZ9ZJvAtr9nd4EQ4HbsUC77WDf

I'm a supporter of BSV, but you are free to use it on BTC/BCH etc.

### License

BSD-2-Clause