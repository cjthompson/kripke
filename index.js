"use strict";
var crypto = require('crypto');
var defaultIterations = 131072;
/**
 * @callback nodeCallback
 * @param err {Error} If set, indicates and error or `null` if there was no error
 * @param result {string}
 */

/**
 * Create an instance with a built-in key that can encrypt and decrypt data
 *
 * @param options.key {string|Buffer} The secret key from which to derive the encryption key
 * @param [options.hmacKey] {string|Buffer} A secret key to use to sign the encoded data
 * @param [options.algorithm] {string} Name of the encryption algorithm to use. Default: 'AES-256-CBC'
 * @param [options.hmacAlgorithm] {string} Name of the hash algorithm to use. Default: 'SHA256'
 * @param [options.iterations] {number} The number of iterations used to generate the derived key. Default: 2^17
 * @param [options.keyLength] {number} The number of bits for the key. Must be 128, 192, or 256. Default: 256
 * @constructor
 */
function Kripke (options) {
  var key, hmacKey, hmacAlgorithm, iterations, keyLength;
  if (!(options && options.key)) {
    throw new TypeError('You must provide a "key"');
  }
  key = options.key;
  hmacKey = options.hmacKey;
  iterations = options.iterations || defaultIterations;
  hmacAlgorithm = options.hmacAlgorithm || 'SHA256';
  if (options.keyLength && [128, 192, 256].indexOf(options.keyLength) > -1) {
    keyLength = options.keyLength / 8;
  } else {
    keyLength = 32;
  }
  this.algorithm = options.algorithm || 'AES-256-CBC';

  /**
   * @callback derivedKeyCallback
   * @param err {Error} If set, indicates and error or `null` if there was no error
   * @param derivedKey {Buffer} The derived key
   * @param [salt] {Buffer} The salt that was used (provided or generated)
   */
  /**
   * Generate a key derived from the secret key
   *
   * @param [salt] {string|Buffer} A base64 encoded-string or Buffer to use as a salt in the key derivation function
   *                               If no `salt` is provided, a random 16 byte salt will be generated and returned in the callback
   * @param callback {derivedKeyCallback}
   */
  this.generateDerivedKey = function (salt, callback) {
    if (!callback && typeof salt === 'function') {
      callback = salt;
      salt = new Buffer(crypto.randomBytes(16));
    }
    if (typeof callback !== 'function') {
      throw new TypeError('Missing callback');
    }
    if (!Buffer.isBuffer(salt)) { salt = new Buffer(salt, 'base64'); }

    crypto.pbkdf2(key, salt, iterations, keyLength, hmacAlgorithm, function (err, derivedKey) {
      callback(err, derivedKey, salt);
    });
  };

  /**
   * Sign the data using the instance `hmacKey`
   *
   * @param data {string|Buffer} Data to sign
   * @returns {string} Returns `data` with the HMAC signature appended ('$' delimited)
   */
  this.sign = function sign (data) {
    var hmac;
    if (hmacKey) {
      hmac = crypto.createHmac(hmacAlgorithm, hmacKey);
      hmac.setEncoding('base64');
      hmac.write(data);
      hmac.end();
      data += ('$' + hmac.read());
    }
    return data;
  };

  /**
   * Verify the HMAC signature on data encoded by the `encrypt` function
   *
   * @param encodedData {string} A '$' delimited string.
   *                             If `hmacKey` was provided OR the `encodedData` contains a signature, then verification is required
   *                             otherwise, return `true` since there's no signature and no key
   * @returns {boolean} Returns `true` if the verification is successful or not required
   */
  this.verify = function verify (encodedData) {
    var hmac, parts = encodedData.split('$');
    if (hmacKey || parts.length === 4) {
      if (!hmacKey) {
        throw new TypeError('An "hmacKey" is required to verify the HMAC signature of the cipher text');
      }
      if (parts.length < 4) {
        throw new TypeError('An "hmacKey" was provided but the cipher text does not include an HMAC signature');
      }

      hmac = crypto.createHmac(hmacAlgorithm, hmacKey);
      hmac.write(encodedData.substr(0, encodedData.lastIndexOf('$')));
      hmac.end();
      return compareBuffers(hmac.read(), new Buffer(parts[3], 'base64'));
    }
    return true;
  };
};

/**
 * Encrypt data using the instance key and a random salt and iv
 *
 * @param plainText {string|Buffer} Data to encrypt
 * @param callback {nodeCallback} Returns a string with the encrypted data, iv, and salt in a '$' delimited string
 */
Kripke.prototype.encrypt = function (plainText, callback) {
  var self = this;
  if (typeof callback !== 'function') {
    throw new TypeError('No callback provided');
  }
  if (!plainText || plainText.length === 0) {
    throw new TypeError('Invalid plain text data');
  }

  this.generateDerivedKey(function (err, derivedKey, salt) {
    var cipher, iv, cipherText, encodedData;

    if (derivedKey && salt) {
      iv = new Buffer(crypto.randomBytes(16));
      // Encrypt the plain text using the derived key
      try {
        cipher = crypto.createCipheriv(self.algorithm, derivedKey, iv);
        cipher.setEncoding('base64');
        cipher.write(plainText);
        cipher.end();
        cipherText = cipher.read();
        // Create the $ delimited string with the iv and salt so it can be decrypted later
        encodedData = self.sign(cipherText + '$' + iv.toString('base64') + '$' + salt.toString('base64'));
      } catch (e) {
        err = e;
      }
    }
    callback(err, encodedData);
  });
};

/**
 * Decrypt data from a string encoded by the `encrypt` function
 *
 * @param encodedText {string} A '$' delimited string that includes the payload, iv, and salt
 * @param callback {nodeCallback} Returns the decrypted data as a utf8 string
 */
Kripke.prototype.decrypt = function (encodedText, callback) {
  var cipherValues, iv, salt, err, self = this;
  if (typeof callback !== 'function') {
    throw new TypeError('No callback provided');
  }
  if (!encodedText || typeof encodedText !== 'string') {
    throw new TypeError('Invalid cipher text');
  }

  // Get iv and salt from the $ delimited cipherText
  cipherValues = encodedText.split("$");
  if (cipherValues && cipherValues.length >= 3) {
    iv = new Buffer(cipherValues[1], 'base64');
    salt = new Buffer(cipherValues[2], 'base64');

    try {
      // Verify the HMAC signature if one is expected
      if (this.verify(encodedText)) {
        this.generateDerivedKey(salt, function (err, derivedKey) {
          var decipher, decryptedText, innerErr;
          if (derivedKey) {
            try {
              decipher = crypto.createDecipheriv(self.algorithm, derivedKey, iv);
              decipher.setEncoding('utf8');
              decipher.write(cipherValues[0], 'base64');
              decipher.end();
              decryptedText = decipher.read();
            } catch (e) {
              innerErr = e;
            }
          }
          callback(innerErr, decryptedText);
        });
      } else {
        err = new Error('HMAC signature verification failed');
      }
    } catch (e) {
      err = e;
    }
  } else {
    err = new TypeError('Encoded text is invalid');
  }
  if (err) { callback(err); }
};

/**
 * Encrypt a plain text payload
 *
 * @static
 * @param plainText {string|Buffer} Plain text to be encrypted
 * @param options {{}}}
 * @param options.key {string|Buffer} The secret key from which to derive the encryption key
 * @param [options.hmacKey] {string|Buffer} A secret key to use to sign the encoded data
 * @param [options.algorithm] {string} Name of the encryption algorithm to use. Default: 'AES-256-CBC'
 * @param [options.hmacAlgorithm] {string} Name of the hash algorithm to use. Default: 'SHA256'
 * @param [options.iterations] {number} The number of iterations used to generate the derived key. Default: 2^17
 * @param callback {nodeCallback} Returns a string with the encrypted data, iv, and salt in a '$' delimited string
 * @throws {Error} No callback provided
 * @throws {TypeError} `options.key` is not provided or `plainText` is not valid
 */
Kripke.encrypt = function (plainText, options, callback) {
  var cipherText, hmac, iv, salt, err;
  if (typeof callback !== 'function') {
    throw new Error('No callback provided');
  }
  if (!options.key) {
    throw new TypeError('You must provide a "key"');
  }
  if (!plainText || plainText.length === 0) {
    throw new TypeError('Invalid plain text data');
  }
  options.algorithm = options.algorithm || 'AES-256-CBC';
  options.hmacAlgorithm = options.hmacAlgorithm || 'SHA256';
  options.iterations = options.iterations || defaultIterations;

  // Generate a `salt` for pbkdf2 and an `iv` for the encryption algorithm
  iv = new Buffer(crypto.randomBytes(16));
  salt = new Buffer(crypto.randomBytes(16));

  try {
    crypto.pbkdf2(options.key, salt, options.iterations, 32, options.hmacAlgorithm, function (err, derivedKey) {
      var cipher, encodedData;

      if (derivedKey) {
        try {
          // Encrypt the plain text using the derived key
          cipher = crypto.createCipheriv(options.algorithm, derivedKey, iv);
          cipher.setEncoding('base64');
          cipher.write(plainText);
          cipher.end();
          cipherText = cipher.read();
          // Create the $ delimited string with the iv and salt so it can be decrypted later
          encodedData = cipherText + '$' + iv.toString('base64') + '$' + salt.toString('base64');

          // Optionally add an HMAC signature to prevent tampering
          if (options.hmacKey) {
            hmac = crypto.createHmac(options.hmacAlgorithm, options.hmacKey);
            hmac.setEncoding('base64');
            hmac.write(encodedData);
            hmac.end();
            encodedData += ('$' + hmac.read());
          }
        } catch (e) {
          err = e;
        }
      }
      callback(err, encodedData);
    });
  } catch (e) {
    err = e;
  }
  if (err) {
    callback(err);
  }
};

/**
 * Decrypt data that was encoded with the `encrypt` function
 *
 * @static
 * @param encodedText {string} Encrypted text as a $ delimited string
 * @param options {{}}}
 * @param options.key {string|Buffer} The secret key from which to derive the encryption key
 * @param [options.hmacKey] {string|Buffer} A secret key to use to sign the encoded data
 * @param [options.algorithm] {string} Name of the encryption algorithm to use. Default: 'AES-256-CBC'
 * @param [options.hmacAlgorithm] {string} Name of the hash algorithm to use. Default: 'SHA256'
 * @param [options.iterations] {number} The number of iterations used to generate the derived key. Default: 2^17
 * @param callback {nodeCallback} Returns the decrypted data as a utf8 string
 * @throws Error If no callback is provided
 */
Kripke.decrypt = function (encodedText, options, callback) {
  var cipherValues, hmac, decipher, iv, salt, err;
  if (typeof callback !== 'function') {
    throw new Error('No callback provided');
  }
  if (!encodedText || typeof encodedText !== 'string') {
    throw new TypeError('Invalid cipher text');
  }
  if (!options.key) {
    throw new TypeError('You must provide a "key"');
  }
  options.algorithm = options.algorithm || 'AES-256-CBC';
  options.hmacAlgorithm = options.hmacAlgorithm || 'SHA256';
  options.iterations = options.iterations || defaultIterations;

  // Get iv and salt from the $ delimited cipherText
  cipherValues = encodedText.split("$");
  iv = new Buffer(cipherValues[1], 'base64');
  salt = new Buffer(cipherValues[2], 'base64');

  // Verify the HMAC signature if one is expected
  if (options.hmacKey || cipherValues.length === 4) {
    if (!options.hmacKey) {
      err = new TypeError('An "hmacKey" is required to verify the HMAC signature of the cipher text');
    } else if (cipherValues.length < 4) {
      err = new TypeError('An "hmacKey" was provided but the cipher text does not include an HMAC signature');
    }

    if (!err) {
      try {
        hmac = crypto.createHmac(options.hmacAlgorithm, options.hmacKey);
        hmac.write(encodedText.substr(0, encodedText.lastIndexOf('$')));
        hmac.end();
        if (!compareBuffers(hmac.read(), new Buffer(cipherValues[3], 'base64'))) {
          err = new Error('HMAC signature verification failed');
        }
      } catch (e) {
        err = e;
      }
    }
  }

  // Decrypt the payload using the derived key
  if (!err) {
    crypto.pbkdf2(options.key, salt, options.iterations, 32, options.hmacAlgorithm, function (err, derivedKey) {
      var decipheredText;
      if (derivedKey) {
        try {
          decipher = crypto.createDecipheriv(options.algorithm, derivedKey, iv);
          decipher.setEncoding('utf8');
          decipher.write(cipherValues[0], 'base64');
          decipher.end();
          decipheredText = decipher.read();
        } catch (e) {
          err = e;
        }
      }
      callback(err, decipheredText);
    });
  }
  if (err) {
    callback(err);
  }
};

/**
 * A constant time compare of two Buffers
 *
 * @param buffer1 {Buffer}
 * @param buffer2 {Buffer}
 * @returns {boolean} Returns `true` only if the contents of the Buffers are identical
 */
function compareBuffers(buffer1, buffer2) {
  if (!(Buffer.isBuffer(buffer1) || Buffer.isBuffer(buffer2))) { return false; }
  if (buffer1.length !== buffer2.length) { return false; }

  var i = 0, val = 0;
  for (; i < buffer1.length; i++) {
    val |= buffer1[i] ^ buffer2[i]; // XOR
  }
  return val === 0;
}

module.exports = Kripke;
