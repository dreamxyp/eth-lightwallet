const CryptoJS = require('crypto-js');
const Transaction = require('happyucjs-tx');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const bitcore = require('bitcore-lib');
const Random = bitcore.crypto.Random;
const Hash = bitcore.crypto.Hash;
const Mnemonic = require('bitcore-mnemonic');
const nacl = require('tweetnacl');
const scrypt = require('scrypt-async');

// const encryption = require('./encryption');
const signing = require('./signing');

function strip0x (input) {

  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length >= 2 && input.slice(0,2) === '0x') {
    return input.slice(2);
  }
  else {
    return input;
  }
}

function add0x (input) {

  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length < 2 || input.slice(0,2) !== '0x') {
    return '0x' + input;
  }
  else {
    return input;
  }
}

function leftPadString (stringToPad, padChar, length) {

  let repreatedPadChar = '';
  for (let i=0; i<length; i++) {
    repreatedPadChar += padChar;
  }

  return ( (repreatedPadChar + stringToPad).slice(-length) );
}


function nacl_encodeHex(msgUInt8Arr) {
  let msgBase64 = nacl.util.encodeBase64(msgUInt8Arr);
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}


function nacl_decodeHex(msgHex) {
  let msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}

function KeyStore(){}

KeyStore.prototype.init = function(mnemonic, pwDerivedKey, hdPathString, salt) {

  this.salt          = salt;
  this.hdPathString  = hdPathString;
  this.encSeed       = undefined;
  this.encHdRootPriv = undefined;
  this.version       = 3;
  this.hdIndex       = 0;
  this.encPrivKeys   = {};
  this.addresses     = [];

  if ( (typeof pwDerivedKey !== 'undefined') && (typeof mnemonic !== 'undefined') ){

    let words = mnemonic.split(' ');
    if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH) || words.length !== 12){
      throw new Error('KeyStore: Invalid mnemonic');
    }

    // Pad the seed to length 120 before encrypting
    let paddedSeed = leftPadString(mnemonic, ' ', 120);
    this.encSeed = encryptString(paddedSeed, pwDerivedKey);

    // hdRoot is the relative root from which we derive the keys using
    // generateNewAddress(). The derived keys are then
    // `hdRoot/hdIndex`.

    let hdRoot    = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    let hdRootKey = new bitcore.HDPrivateKey(hdRoot);
    let hdPathKey = hdRootKey.derive(hdPathString).xprivkey;
    this.encHdRootPriv = encryptString(hdPathKey, pwDerivedKey);
  }

}

KeyStore.createVault = function(opts, cb) {
  // Default hdPathString
  if (!('hdPathString' in opts)) {
    let err = new Error("Keystore: Must include hdPathString in createVault inputs. Suggested alternatives are m/0'/0'/0' for previous lightwallet default, or m/44'/60'/0'/0 for BIP44 (used by Jaxx & MetaMask)")
    return cb(err)
  }

  if (!('seedPhrase' in opts)) {
    let err = new Error('Keystore: Must include seedPhrase in createVault inputs.')
    return cb(err)
  }

  if (!('salt' in opts)) {
    opts.salt = generateSalt(32);
  }

  KeyStore.deriveKeyFromPasswordAndSalt(opts.password, opts.salt, function(err, pwDerivedKey) {
    if (err) return cb(err);

    let ks = new KeyStore();
    ks.init(opts.seedPhrase, pwDerivedKey, opts.hdPathString, opts.salt);

    cb(null, ks);
  });
};

KeyStore.generateSalt = generateSalt;

function generateSalt (byteCount) {
  return bitcore.crypto.Random.getRandomBuffer(byteCount || 32).toString('base64');
}

KeyStore.prototype.isDerivedKeyCorrect = function(pwDerivedKey) {

  let paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);
  if (paddedSeed.length > 0) {
    return true;
  }

  return false;

};

function encryptString (string, pwDerivedKey) {
  let nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  let encObj = nacl.secretbox(nacl.util.decodeUTF8(string), nonce, pwDerivedKey);
  let encString = { 'encStr': nacl.util.encodeBase64(encObj),
                    'nonce': nacl.util.encodeBase64(nonce)};
  return encString;
};
KeyStore._encryptString = encryptString

KeyStore._decryptString = function (encryptedStr, pwDerivedKey) {

  let secretbox = nacl.util.decodeBase64(encryptedStr.encStr);
  let nonce = nacl.util.decodeBase64(encryptedStr.nonce);

  let decryptedStr = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

  if (decryptedStr === undefined) {
    throw new Error("Decryption failed!");
  }

  return nacl.util.encodeUTF8(decryptedStr);
};

KeyStore._encryptKey = function (privKey, pwDerivedKey) {

  let privKeyArray = nacl_decodeHex(privKey);
  let nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  let encKey = nacl.secretbox(privKeyArray, nonce, pwDerivedKey);
  encKey = { 'key': nacl.util.encodeBase64(encKey), 'nonce': nacl.util.encodeBase64(nonce)};

  return encKey;
};

KeyStore._decryptKey = function (encryptedKey, pwDerivedKey) {

  let secretbox = nacl.util.decodeBase64(encryptedKey.key);
  let nonce = nacl.util.decodeBase64(encryptedKey.nonce);
  let decryptedKey = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

  if (decryptedKey === undefined) {
    throw new Error("Decryption failed!");
  }

  return nacl_encodeHex(decryptedKey);
};

KeyStore._computeAddressFromPrivKey = function (privKey) {
  let keyPair = ec.genKeyPair();
  keyPair._importPrivate(privKey, 'hex');
  let compact = false;
  let pubKey = keyPair.getPublic(compact, 'hex').slice(2);
  let pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey);
  let hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 });
  let address = hash.toString(CryptoJS.enc.Hex).slice(24);

  return address;
};

KeyStore._computePubkeyFromPrivKey = function (privKey, curve) {

  if (curve !== 'curve25519') {
    throw new Error('KeyStore._computePubkeyFromPrivKey: Only "curve25519" supported.')
  }

  let privKeyBase64 = (new Buffer(privKey, 'hex')).toString('base64')
  let privKeyUInt8Array = nacl.util.decodeBase64(privKeyBase64);
  let pubKey = nacl.box.keyPair.fromSecretKey(privKeyUInt8Array).publicKey;
  let pubKeyBase64 = nacl.util.encodeBase64(pubKey);
  let pubKeyHex = (new Buffer(pubKeyBase64, 'base64')).toString('hex');

  return pubKeyHex;
}


KeyStore.prototype._generatePrivKeys = function(pwDerivedKey, n) {

  if(!this.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let hdRoot = KeyStore._decryptString(this.encHdRootPriv, pwDerivedKey);

  if (hdRoot.length === 0) {
    throw new Error('Provided password derived key is wrong');
  }

  let keys = [];
  for (let i = 0; i < n; i++){
    let hdprivkey = new bitcore.HDPrivateKey(hdRoot).derive(this.hdIndex++);
    let privkeyBuf = hdprivkey.privateKey.toBuffer();

    let privkeyHex = privkeyBuf.toString('hex');
    if (privkeyBuf.length < 16) {
      // Way too small key, something must have gone wrong
      // Halt and catch fire
      throw new Error('Private key suspiciously small: < 16 bytes. Aborting!');
    }
    else if (privkeyBuf.length < 32) {
      // Pad private key if too short
      // bitcore has a bug where it sometimes returns
      // truncated keys
      privkeyHex = leftPadString(privkeyBuf.toString('hex'), '0', 64);
    }
    else if (privkeyBuf.length > 32) {
      throw new Error('Private key larger than 32 bytes. Aborting!');
    }

    let encPrivKey = KeyStore._encryptKey(privkeyHex, pwDerivedKey);
    keys[i] = {
      privKey: privkeyHex,
      encPrivKey: encPrivKey
    }
  }

  return keys;
};


// This function is tested using the test vectors here:
// http://www.di-mgt.com.au/sha_testvectors.html
KeyStore._concatAndSha256 = function(entropyBuf0, entropyBuf1) {

  let totalEnt = Buffer.concat([entropyBuf0, entropyBuf1]);
  if (totalEnt.length !== entropyBuf0.length + entropyBuf1.length) {
    throw new Error('generateRandomSeed: Logic error! Concatenation of entropy sources failed.')
  }

  let hashedEnt = Hash.sha256(totalEnt);

  return hashedEnt;
}

// External static functions


// Generates a random seed. If the optional string
// extraEntropy is set, a random set of entropy
// is created, then concatenated with extraEntropy
// and hashed to produce the entropy that gives the seed.
// Thus if extraEntropy comes from a high-entropy source
// (like dice) it can give some protection from a bad RNG.
// If extraEntropy is not set, the random number generator
// is used directly.

KeyStore.generateRandomSeed = function(extraEntropy) {

  let seed = '';
  if (extraEntropy === undefined) {
    seed = new Mnemonic(Mnemonic.Words.ENGLISH);
  }
  else if (typeof extraEntropy === 'string') {
    let entBuf = new Buffer(extraEntropy);
    let randBuf = Random.getRandomBuffer(256 / 8);
    let hashedEnt = this._concatAndSha256(randBuf, entBuf).slice(0, 128 / 8);
    seed = new Mnemonic(hashedEnt, Mnemonic.Words.ENGLISH);
  }
  else {
    throw new Error('generateRandomSeed: extraEntropy is set but not a string.')
  }

  return seed.toString();
};

KeyStore.isSeedValid = function(seed) {
  return Mnemonic.isValid(seed, Mnemonic.Words.ENGLISH)
};

// Takes keystore serialized as string and returns an instance of KeyStore
KeyStore.deserialize = function (keystore) {
  let jsonKS = JSON.parse(keystore);

  if (jsonKS.version === undefined || jsonKS.version !== 3) {
    throw new Error('Old version of serialized keystore. Please use KeyStore.upgradeOldSerialized() to convert it to the latest version.')
  }

  // Create keystore
  let keystoreX = new KeyStore();

  keystoreX.salt = jsonKS.salt
  keystoreX.hdPathString = jsonKS.hdPathString
  keystoreX.encSeed = jsonKS.encSeed;
  keystoreX.encHdRootPriv = jsonKS.encHdRootPriv;
  keystoreX.version = jsonKS.version;
  keystoreX.hdIndex = jsonKS.hdIndex;
  keystoreX.encPrivKeys = jsonKS.encPrivKeys;
  keystoreX.addresses = jsonKS.addresses;

  return keystoreX;
};

KeyStore.deriveKeyFromPasswordAndSalt = function(password, salt, callback) {

  // Do not require salt, and default it to 'lightwalletSalt'
  // (for backwards compatibility)
  if (!callback && typeof salt === 'function') {
    callback = salt
    salt = 'lightwalletSalt'
  } else if (!salt && typeof callback === 'function') {
    salt = 'lightwalletSalt'
  }

  let logN = 14;
  let r = 8;
  let dkLen = 32;
  let interruptStep = 200;

  let cb = function(derKey) {
    let err = null
    let ui8arr = null
    try{
      ui8arr = (new Uint8Array(derKey));
    } catch (e) {
      err = e
    }
    callback(err, ui8arr);
  }
  scrypt(password, salt, logN, r, dkLen, interruptStep, cb, null);
}

// External API functions

KeyStore.prototype.serialize = function () {
  let jsonKS = {'encSeed': this.encSeed,
                'encHdRootPriv' : this.encHdRootPriv,
                'addresses' : this.addresses,
                'encPrivKeys' : this.encPrivKeys,
                'hdPathString' : this.hdPathString,
                'salt': this.salt,
                'hdIndex' : this.hdIndex,
                'version' : this.version};

  return JSON.stringify(jsonKS);
};

KeyStore.prototype.getAddresses = function () {

  let prefixedAddresses = this.addresses.map(function (addr) {
    return add0x(addr)
  });
  return prefixedAddresses;
};


KeyStore.prototype.getSeed = function (pwDerivedKey) {

  if(!this.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }
  let paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);
  return paddedSeed.trim();
};

KeyStore.prototype.exportPrivateKey = function (address0, pwDerivedKey) {

  if(!this.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let address = strip0x(address0).toLowerCase();
  if (this.encPrivKeys[address] === undefined) {
    throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
  }

  let encPrivKey = this.encPrivKeys[address];
  let privKey = KeyStore._decryptKey(encPrivKey, pwDerivedKey);

  return privKey;
};

KeyStore.prototype.generateNewAddress = function(pwDerivedKey, n) {

  if(!this.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  if (!this.encSeed) {
    throw new Error('KeyStore.generateNewAddress: No seed set');
  }
  n = n || 1;
  let keys = this._generatePrivKeys(pwDerivedKey, n);

  for (let i = 0; i < n; i++) {
    let keyObj = keys[i];
    let address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);
    this.encPrivKeys[address] = keyObj.encPrivKey;
    this.addresses.push(address);
  }

};

KeyStore.prototype.keyFromPassword = function(password, callback) {
  KeyStore.deriveKeyFromPasswordAndSalt(password, this.salt, callback);
}


// Async functions exposed for Hooked Webu-provider
// hasAddress(address, callback)
// signTransaction(txParams, callback)
//
// The function signTransaction() needs the
// function KeyStore.prototype.passwordProvider(callback)
// to be set in order to run properly.
// The function passwordProvider is an async function
// that calls the callback(err, password) with a password
// supplied by the user or by other means.
// The user of the hooked webu-provider is encouraged
// to write their own passwordProvider.
//
// Uses defaultHdPathString for the addresses.

KeyStore.prototype.passwordProvider = function (callback)
{
  let password = prompt("Enter password to continue","Enter password");
  callback(null, password);
}


KeyStore.prototype.hasAddress = function (address, callback) {
  let addrToCheck = strip0x(address);
  if (this.encPrivKeys[addrToCheck] === undefined) {
    callback('Address not found!', false);
  }
  else {
    callback(null, true);
  }
};

KeyStore.prototype.signTransaction = function (txParams, callback) {
  let hucjsTxParams = {};
      hucjsTxParams.from     = add0x(txParams.from);
      hucjsTxParams.to       = add0x(txParams.to);
      hucjsTxParams.gasLimit = add0x(txParams.gas);
      hucjsTxParams.gasPrice = add0x(txParams.gasPrice);
      hucjsTxParams.nonce    = add0x(txParams.nonce);
      hucjsTxParams.value    = add0x(txParams.value);
      hucjsTxParams.data     = add0x(txParams.data);


  let txObj          = new Transaction(hucjsTxParams);
  let rawTx          = txObj.serialize().toString('hex');
  let signingAddress = strip0x(txParams.from);
  let salt           = this.salt;
  let self           = this;
  this.passwordProvider( function (err, password, salt) {
    if (err) return callback(err);
    if (!salt) {
      salt = self.salt
    }

    self.keyFromPassword(password, function (err, pwDerivedKey) {
      if (err) return callback(err);
      let signedTx = signing.signTx(self, pwDerivedKey, rawTx, signingAddress, self.defaultHdPathString);
      callback(null, '0x' + signedTx);
    })
  })

};


module.exports = KeyStore;
