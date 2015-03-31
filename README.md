Kripke
======

Simple ciphering module that encrypts files using pbkdf2 to generate an encryption
key from a secret.  A random 128-bit salt and separate random 128-bit iv are used.

## Installation

```
npm install kripke
```

## API

### options
| Option | Value |
|--------|-------|
| `key`  | A string or Buffer that's used in pbkdf2 to generate a 256-bit encryption key |
| `hmacKey` | (optional) A string or Buffer used as an HMAC secret to sign the encrypted data.  If not provided, then HMAC signing is disabled. |
| `algorithm` | (optional) The name of the encryption algorithm to use.  Default is 'AES-256-CBC' |
| `hmacAlgorithm` | (optional) The name of the hash algorithm to use with HMAC signing.  Default is 'SHA256' |
| `iterations` | (optional) The number of iterations to use in pbkdf2. Default is 2^17 (131072) |

### Instance functions
You can create an instance of Kripke with the key and options (stored in private variables). 

| Function | Parameters | Purpose |
|--------|-------|-------|
| `encrypt` | `plainText`, `callback` | Returns a UTF8 string containing base64 encoded values of the cipher text, iv, salt, and optional HMAC signature. String is `$` delimited.
| `decrypt` | `encodedText`, `callback` | Returns a UTF8 string of the decrypted data
 
```javascript
  var Kripke = require('kripke');
  var options = {
    key: process.env.MYAPP_SECRET_KEY, // 'yfghsdfgsdfhdfgh'
    hmacKey: process.env.MYAPP_HMAC_KEY, // '8y34u5ihlksjfg981'
  };
  var kripke = new Kripke(options);
    
  // Encrypt data
  kripke.encrypt('My secret data', function (err, result) {
    // result = 'UJoHS9jcZlillPUdsP2Blw==$kZTq/d9cFa3nq2b7nefM5Q==$b42M4KAPS302I6PCGS10hQ==$bXmfi5pTenDGQz5SMM1v84tO+GKaeNYw+fQJgIk9Y5E='
    model.set('secret', result);
  });
  
  kripke.decrypt(model.get('secret'), function (err, result) {
    // result = 'My secret data'
  });
```

### Static functions
| Function | Parameters | Purpose |
|--------|-------|-------|
| `encrypt` | `plainText`, `options`, `callback` | Using the `options` provided, returns a UTF8 string containing base64 encoded values of the cipher text, iv, salt, and optional HMAC signature. String is `$` delimited.
| `decrypt` | `encodedText`, `options`, `callback` | Using the `options` provided, returns a UTF8 string of the decrypted data
 
```javascript
  var Kripke = require('kripke');
  var options = {
    key: process.env.MYAPP_SECRET_KEY, // 'yfghsdfgsdfhdfgh'
    hmacKey: process.env.MYAPP_HMAC_KEY, // '8y34u5ihlksjfg981'
  };
    
  // Encrypt data
  Kripke.encrypt('My secret data', options, function (err, result) {
    // result = 'UJoHS9jcZlillPUdsP2Blw==$kZTq/d9cFa3nq2b7nefM5Q==$b42M4KAPS302I6PCGS10hQ==$bXmfi5pTenDGQz5SMM1v84tO+GKaeNYw+fQJgIk9Y5E='
    model.set('secret', result);
  });
  
  Kripke.decrypt(model.get('secret'), options, function (err, result) {
    // result = 'My secret data'
  });
```
