"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getTokenFromGCPServiceAccount = exports.getToken = exports.getHeader = exports.algorithms = void 0;

var _utils = require("./utils");

require("@sagi.io/globalthis");

var _jsBase = require("js-base64");

const algorithms = {
  RS256: {
    name: 'RSASSA-PKCS1-v1_5',
    hash: {
      name: 'SHA-256'
    }
  },
  ES256: {
    name: 'ECDSA',
    namedCurve: 'P-256',
    hash: {
      name: 'SHA-256'
    }
  }
};
exports.algorithms = algorithms;

const getHeader = (alg, headerAdditions) => ({ ...headerAdditions,
  alg,
  typ: 'JWT'
}); // XXX https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth


exports.getHeader = getHeader;

const getToken = async ({
  privateKeyPEM,
  payload,
  alg = 'RS256',
  cryptoImpl = null,
  headerAdditions = {}
}) => {
  const algorithm = algorithms[alg];

  if (!algorithm) {
    throw new Error(`@sagi.io/workers-jwt: Unsupported algorithm ${alg}.`);
  }

  if (!globalThis.crypto) {
    if (!cryptoImpl) {
      throw new Error(`@sagi.io/workers-jwt: No crypto nor cryptoImpl were found.`);
    }

    globalThis.crypto = cryptoImpl;
  }

  const privateKeyDER = (0, _utils.getDERfromPEM)(privateKeyPEM);
  const privateKey = await globalThis.crypto.subtle.importKey('pkcs8', privateKeyDER, algorithm, false, ['sign']);
  const header = getHeader(alg, headerAdditions);
  const encodedMessage = (0, _utils.getEncodedMessage)(header, payload);
  const encodedMessageArrBuf = (0, _utils.str2ab)(encodedMessage);
  const signatureArrBuf = await globalThis.crypto.subtle.sign(algorithm, privateKey, encodedMessageArrBuf);
  const signatureUint8Array = new Uint8Array(signatureArrBuf);

  const encodedSignature = _jsBase.Base64.fromUint8Array(signatureUint8Array, true);

  const token = `${encodedMessage}.${encodedSignature}`;
  return token;
}; // Service Account Authoriazation without OAuth2:
// https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth
// Service Account Auth for OAuth2 Tokens: Choose "HTTP / REST" for:
// https://developers.google.com/identity/protocols/OAuth2ServiceAccount


exports.getToken = getToken;

const getTokenFromGCPServiceAccount = async ({
  serviceAccountJSON,
  aud,
  alg = 'RS256',
  cryptoImpl = null,
  expiredAfter = 3600,
  headerAdditions = {},
  payloadAdditions = {}
}) => {
  const {
    client_email: clientEmail,
    private_key_id: privateKeyId,
    private_key: privateKeyPEM
  } = serviceAccountJSON;
  Object.assign(headerAdditions, {
    kid: privateKeyId
  });
  const header = getHeader(alg, headerAdditions);
  const iat = parseInt(Date.now() / 1000);
  const exp = iat + expiredAfter;
  const iss = clientEmail;
  const sub = clientEmail;
  const payload = {
    aud,
    iss,
    sub,
    iat,
    exp,
    ...payloadAdditions
  };
  return getToken({
    privateKeyPEM,
    payload,
    alg,
    headerAdditions,
    cryptoImpl
  });
};

exports.getTokenFromGCPServiceAccount = getTokenFromGCPServiceAccount;