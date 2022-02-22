"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getEncodedMessage = exports.b64encodeJSON = exports.getDERfromPEM = exports.str2ab = void 0;

require("@sagi.io/globalthis");

var _jsBase = require("js-base64");

const str2ab = str => {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);

  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }

  return buf;
};

exports.str2ab = str2ab;

const getDERfromPEM = pem => {
  const pemB64 = pem.trim().split('\n').slice(1, -1) // Remove the --- BEGIN / END PRIVATE KEY ---
  .join('');
  return str2ab(_jsBase.Base64.atob(pemB64));
};

exports.getDERfromPEM = getDERfromPEM;

const b64encodeJSON = obj => _jsBase.Base64.encode(JSON.stringify(obj), true);

exports.b64encodeJSON = b64encodeJSON;

const getEncodedMessage = (header, payload) => {
  const encodedHeader = b64encodeJSON(header);
  const encodedPayload = b64encodeJSON(payload);
  const encodedMessage = `${encodedHeader}.${encodedPayload}`;
  return encodedMessage;
};

exports.getEncodedMessage = getEncodedMessage;