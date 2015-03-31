"use strict";

var assert = require('assert');
var crypto = require('crypto');
var Kripke = require('../index');

describe('Instance tests', function () {
  var k, data, options;

  beforeEach(function () {
    data = crypto.randomBytes(64).toString('hex');
    options = {
      key: crypto.randomBytes(32),
      iterations: 10000
    };
  });

  describe('Without HMAC', function () {
    beforeEach(function () {
      k = new Kripke(options);
    });

    it('should encrypt data', function (done) {
      k.encrypt(data, function (e, r) {
        assert.equal(e, undefined);
        assert.equal(typeof r, 'string');
        assert.equal(r.split('$').length, 3);
        done();
      })
    });

    it('should decrypt data', function (done) {
      k.encrypt(data, function (e, r) {
        assert(typeof r, 'string');
        k.decrypt(r, function (err, result) {
          assert.equal(err, undefined);
          assert.equal(typeof result, 'string');
          assert.equal(result, data);
          done();
        })
      })
    });
  });

  describe('With HMAC', function () {
    beforeEach(function () {
      options.hmacKey = crypto.randomBytes(32);
      k = new Kripke(options);
    });

    it('should encrypt data', function (done) {
      k.encrypt(data, function (e, r) {
        assert.equal(e, undefined);
        assert.equal(typeof r, 'string');
        // Should have extra HMAC signature
        assert.equal(r.split('$').length, 4);
        done();
      })
    });

    it('should decrypt data', function (done) {
      k.encrypt(data, function (e, r) {
        assert(typeof r, 'string');
        k.decrypt(r, function (err, result) {
          assert.equal(err, undefined);
          assert.equal(typeof result, 'string');
          assert.equal(result, data);
          done();
        })
      })
    });

    it('should require hmacKey if data contains a signature', function (done) {
      k.encrypt(data, function (e, r) {
        assert(typeof r, 'string');
        delete options.hmacKey;
        var k2 = new Kripke(options);
        k2.decrypt(r, function (err, result) {
          assert(err instanceof Error);
          assert.equal(err.message, 'An "hmacKey" is required to verify the HMAC signature of the cipher text');
          assert.equal(result, undefined);
          done();
        })
      })
    });

    it('should require an hmac signature if hmacKey is provided', function (done) {
      delete options.hmacKey;
      var k2 = new Kripke(options);
      k2.encrypt(data, function (e, r) {
        assert(typeof r, 'string');
        k.decrypt(r, function (err, result) {
          assert(err instanceof Error);
          assert.equal(err.message, 'An "hmacKey" was provided but the cipher text does not include an HMAC signature');
          assert.equal(result, undefined);
          done();
        })
      })
    });
  });

  describe('Error handling', function () {
    it('should throw an error on missing callback', function () {
      assert.throws(k.encrypt, /No callback provided/);
      assert.throws(k.decrypt, /No callback provided/);
    });

    it('should throw an error if data is invalid', function () {
      assert.throws(function () {
        k.encrypt('', function () {});
      }, /Invalid plain text data/);
      assert.throws(function () {
        k.encrypt(null, function () {});
      }, /Invalid plain text data/);
      assert.throws(function () {
        k.encrypt(new Buffer(''), function () {});
      }, /Invalid plain text data/);
      assert.throws(function () {
        k.decrypt('', function () {});
      }, /Invalid cipher text/);
      assert.throws(function () {
        k.decrypt(null, function () {});
      }, /Invalid cipher text/);
      assert.throws(function () {
        k.decrypt(new Buffer(''), function () {});
      }, /Invalid cipher text/);
    });

    it('should throw an error if key is missing', function () {
      assert.throws(function () {
        new Kripke({});
      }, /You must provide a "key"/);
    });

    it('should return an error if the HMAC validation fails', function (done) {
      options.hmacKey = crypto.randomBytes(32);
      k = new Kripke(options);
      k.encrypt(data, function (e, r) {
        r = r.substr(0, 10) + '0' + r.substr(11);
        k.decrypt(r, function (err) {
          assert(err instanceof Error);
          assert.equal(err.message, 'HMAC signature verification failed');
          done();
        })
      })
    });
  });
});

describe('Static functions', function () {
  var k, data, options;

  beforeEach(function () {
    data = crypto.randomBytes(64).toString('hex');
    options = {
      key: crypto.randomBytes(32),
      iterations: 10000
    };
  });

  describe('Without HMAC', function () {
    it('should encrypt data', function (done) {
      Kripke.encrypt(data, options, function (e, r) {
        assert.equal(e, undefined);
        assert.equal(typeof r, 'string');
        assert.equal(r.split('$').length, 3);
        done();
      })
    });

    it('should decrypt data', function (done) {
      Kripke.encrypt(data, options, function (e, r) {
        assert(typeof r, 'string');
        Kripke.decrypt(r, options, function (err, result) {
          assert.equal(err, undefined);
          assert.equal(typeof result, 'string');
          assert.equal(result, data);
          done();
        })
      })
    });
  });

  describe('With HMAC', function () {
    beforeEach(function () {
      options.hmacKey = crypto.randomBytes(64).toString('hex');
    });

    it('should encrypt data', function (done) {
      Kripke.encrypt(data, options, function (e, r) {
        assert.equal(e, undefined);
        assert.equal(typeof r, 'string');
        // Should have extra HMAC signature
        assert.equal(r.split('$').length, 4);
        done();
      })
    });

    it('should decrypt data', function (done) {
      Kripke.encrypt(data, options, function (e, r) {
        assert(typeof r, 'string');
        Kripke.decrypt(r, options, function (err, result) {
          assert.equal(err, undefined);
          assert.equal(typeof result, 'string');
          assert.equal(result, data);
          done();
        })
      })
    });

    it('should require hmacKey if data contains a signature', function (done) {
      Kripke.encrypt(data, options, function (e, r) {
        assert(typeof r, 'string');
        delete options.hmacKey;
        Kripke.decrypt(r, options, function (err, result) {
          assert(err instanceof Error);
          assert.equal(err.message, 'An "hmacKey" is required to verify the HMAC signature of the cipher text');
          assert.equal(result, undefined);
          done();
        })
      })
    });

    it('should require an hmac signature if hmacKey is provided', function (done) {
      var noHmac = { key: options.key, iterations: options.iterations };
      Kripke.encrypt(data, noHmac, function (e, r) {
        assert(typeof r, 'string');
        Kripke.decrypt(r, options, function (err, result) {
          assert(err instanceof Error);
          assert.equal(err.message, 'An "hmacKey" was provided but the cipher text does not include an HMAC signature');
          assert.equal(result, undefined);
          done();
        })
      })
    });
  });

  describe('Error handling', function () {
    it('should throw an error on missing callback', function () {
      assert.throws(Kripke.encrypt, /No callback provided/);
      assert.throws(Kripke.decrypt, /No callback provided/);
    });

    it('should throw an error if data is invalid', function () {
      assert.throws(function () {
        Kripke.encrypt('', { key: '1' }, function () {});
      }, /Invalid plain text data/);
      assert.throws(function () {
        Kripke.encrypt(null, { key: '1' }, function () {});
      }, /Invalid plain text data/);
      assert.throws(function () {
        Kripke.encrypt(new Buffer(''), { key: '1' }, function () {});
      }, /Invalid plain text data/);
      assert.throws(function () {
        Kripke.decrypt('', { key: '1' }, function () {});
      }, /Invalid cipher text/);
      assert.throws(function () {
        Kripke.decrypt(null, { key: '1' }, function () {});
      }, /Invalid cipher text/);
      assert.throws(function () {
        Kripke.decrypt(new Buffer(''), { key: '1' }, function () {});
      }, /Invalid cipher text/);
    });

    it('should throw an error if key is missing', function () {
      assert.throws(function () {
        Kripke.encrypt('blah', {}, function () {});
      }, /You must provide a "key"/);
      assert.throws(function () {
        Kripke.decrypt('blah', {}, function () {});
      }, /You must provide a "key"/);
    });

    it('should return an error if the HMAC validation fails', function (done) {
      options.hmacKey = crypto.randomBytes(32);
      Kripke.encrypt(data, options, function (e, r) {
        r = r.substr(0, 10) + '0' + r.substr(11);
        Kripke.decrypt(r, options, function (err) {
          assert(err instanceof Error);
          assert.equal(err.message, 'HMAC signature verification failed');
          done();
        })
      })
    });
  });

});
