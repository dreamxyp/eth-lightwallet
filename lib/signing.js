var Tx   = require("happyucjs-tx")
var util = require("happyucjs-util")

/**
 *
 * @param keystore
 * @param pwDerivedKey
 * @param rawTx
 * @param signingAddress
 * @returns {*}
 */
function signTx(keystore, pwDerivedKey, rawTx, signingAddress){

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }
  
  rawTx = util.stripHexPrefix(rawTx);
  signingAddress = util.stripHexPrefix(signingAddress);

  let txCopy  = new Tx(new Buffer(rawTx, 'hex'));
  let privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey);

  txCopy.sign(new Buffer(privKey, 'hex'));

  return txCopy.serialize().toString('hex');
}

/**
 *
 * @param keystore
 * @param pwDerivedKey
 * @param rawMsg
 * @param signingAddress
 * @returns {Object}
 */
function signMsg(keystore, pwDerivedKey, rawMsg, signingAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  let msgHash = util.addHexPrefix(util.sha3(rawMsg).toString('hex'));
  return this.signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress);
}

/**
 *
 * @param keystore
 * @param pwDerivedKey
 * @param msgHash
 * @param signingAddress
 * @returns {Object}
 */
function signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  signingAddress = util.stripHexPrefix(signingAddress);

  let privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey);
  return util.ecsign(new Buffer(util.stripHexPrefix(msgHash), 'hex'), new Buffer(privKey, 'hex'));
}

/**
 *
 * @param rawMsg
 * @param v
 * @param r
 * @param s
 */
function recoverAddress(rawMsg, v, r, s)
{
  let msgHash = util.sha3(rawMsg);
  return util.pubToAddress(util.ecrecover(msgHash, v, r, s));
}

/**
 *
 * @param signature
 * @returns {String}
 */
function concatSig(signature) {
  let v = signature.v;
  let r = signature.r;
  let s = signature.s;
  r = util.fromSigned(r);
  s = util.fromSigned(s);
  v = util.bufferToInt(v);
  r = util.setLengthLeft(util.toUnsigned(r), 32).toString('hex');
  s = util.setLengthLeft(util.toUnsigned(s), 32).toString('hex');
  v = util.stripHexPrefix(util.intToHex(v));
  return util.addHexPrefix(r.concat(s, v).toString("hex"));
}

module.exports = {
    signTx,
    signMsg,
    signMsgHash,
    recoverAddress,
    concatSig
};
