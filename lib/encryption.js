const util = require("happyucjs-util");
const nacl = require('tweetnacl');

function nacl_encodeHex(msgUInt8Arr) {
  let msgBase64 = nacl.util.encodeBase64(msgUInt8Arr);
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}


function nacl_decodeHex(msgHex) {
  let msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}


function addressToPublicEncKey (keystore, pwDerivedKey, address) {

  let privKey = keystore.exportPrivateKey(address, pwDerivedKey)
  let privKeyUInt8Array = nacl_decodeHex(privKey)
  let pubKeyUInt8Array = nacl.box.keyPair.fromSecretKey(privKeyUInt8Array).publicKey
  return nacl_encodeHex(pubKeyUInt8Array)
}


function _asymEncryptRaw (keystore, pwDerivedKey, msgUint8Array, myAddress, theirPubKey) {
  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let privKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  let privKeyUInt8Array = nacl_decodeHex(privKey);
  let pubKeyUInt8Array = nacl_decodeHex(theirPubKey);
  let nonce = nacl.randomBytes(nacl.box.nonceLength);
  let encryptedMessage = nacl.box(msgUint8Array, nonce, pubKeyUInt8Array, privKeyUInt8Array);

  let output = {
    alg       : 'curve25519-xsalsa20-poly1305',
    nonce     : nacl.util.encodeBase64(nonce),
    ciphertext: nacl.util.encodeBase64(encryptedMessage)
  };

  return output;
}

function _asymDecryptRaw (keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let privKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  let privKeyUInt8Array = nacl_decodeHex(privKey);
  let pubKeyUInt8Array = nacl_decodeHex(theirPubKey);

  let nonce       = nacl.util.decodeBase64(encMsg.nonce);
  let ciphertext  = nacl.util.decodeBase64(encMsg.ciphertext);
  let cleartext   = nacl.box.open(ciphertext, nonce, pubKeyUInt8Array, privKeyUInt8Array);

  return cleartext;
}

function asymEncryptString(keystore, pwDerivedKey, msg, myAddress, theirPubKey) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let messageUInt8Array = nacl.util.decodeUTF8(msg);

  return _asymEncryptRaw(keystore, pwDerivedKey, messageUInt8Array, myAddress, theirPubKey);

}

function asymDecryptString(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let cleartext = _asymDecryptRaw(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress);

  if (cleartext === false) {
    return false;
  }
  else {
    return nacl.util.encodeUTF8(cleartext);
  }
}


function multiEncryptString(keystore, pwDerivedKey, msg, myAddress, theirPubKeyArray) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let messageUInt8Array = nacl.util.decodeUTF8(msg);
  let symEncryptionKey = nacl.randomBytes(nacl.secretbox.keyLength);
  let symNonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  let symEncMessage = nacl.secretbox(messageUInt8Array, symNonce, symEncryptionKey);

  if (theirPubKeyArray.length < 1) {
    throw new Error('Found no pubkeys to encrypt to.');
  }

  const encryptedSymKey = []
  for (let i=0; i<theirPubKeyArray.length; i++) {

    let encSymKey = _asymEncryptRaw(keystore, pwDerivedKey, symEncryptionKey, myAddress, theirPubKeyArray[i]);

    delete encSymKey['alg'];
    encryptedSymKey.push(encSymKey);
  }

  let output = {};
  output.version = 1;
  output.asymAlg = 'curve25519-xsalsa20-poly1305';
  output.symAlg = 'xsalsa20-poly1305';
  output.symNonce = nacl.util.encodeBase64(symNonce);
  output.symEncMessage = nacl.util.encodeBase64(symEncMessage);
  output.encryptedSymKey = encryptedSymKey;

  return output;
}

function multiDecryptString(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let symKey = false;
  for (let i=0; i < encMsg.encryptedSymKey.length; i++) {
    let result = _asymDecryptRaw(keystore, pwDerivedKey, encMsg.encryptedSymKey[i], theirPubKey, myAddress)
    if (result !== false) {
      symKey = result;
      break;
    }
  }

  if (symKey === false) {
    return false;
  }
  else {
    let symNonce = nacl.util.decodeBase64(encMsg.symNonce);
    let symEncMessage = nacl.util.decodeBase64(encMsg.symEncMessage);
    let msg = nacl.secretbox.open(symEncMessage, symNonce, symKey);

    if (msg === false) {
      return false;
    }
    else {
      return nacl.util.encodeUTF8(msg);
    }
  }
}

module.exports = {
  asymEncryptString,
  asymDecryptString,
  multiEncryptString,
  multiDecryptString,
  addressToPublicEncKey
};
