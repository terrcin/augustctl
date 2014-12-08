'use strict';

var Promise = require('bluebird');
var crypto = require('crypto');
var debug = require('debug')('august');
var events = require('events');
var noble = require('noble');
var util = require('util');
var _ = require('underscore');

// promisification of noble
Promise.promisifyAll(require('noble/lib/characteristic').prototype);
Promise.promisifyAll(require('noble/lib/peripheral').prototype);
Promise.promisifyAll(require('noble/lib/service').prototype);

// Calculates the security checksum of a command buffer.
function securityChecksum(buffer) {
  return (0 - (buffer.readUInt32LE(0x00) + buffer.readUInt32LE(0x04) + buffer.readUInt32LE(0x08))) >>> 0;
}

///
// LockSession

function LockSession(writeCharacteristic, readCharacteristic, isSecure) {
  if (!writeCharacteristic || !readCharacteristic) {
    throw new Error('write and/or read characteristic not found');
  }
  this._writeCharacteristic = writeCharacteristic;
  this._readCharacteristic = readCharacteristic;
  this._isSecure = isSecure;
  return this;
}

util.inherits(LockSession, events.EventEmitter);

LockSession.prototype.setKey = function(key) {
  var cipherSuite, iv;
  if (this._isSecure) {
    cipherSuite = 'aes-128-ecb';
    iv = '';
  } else {
    cipherSuite = 'aes-128-cbc';
    iv = new Buffer(0x10);
    iv.fill(0);
  }

  this._encryptCipher = crypto.createCipheriv(cipherSuite, key, iv);
  this._encryptCipher.setAutoPadding(false);
  this._decryptCipher = crypto.createDecipheriv(cipherSuite, key, iv);
  this._decryptCipher.setAutoPadding(false);
};

LockSession.prototype.start = function() {
  // decrypt all reads, modifying the buffer in place
  this._readCharacteristic.on('read', function(data, isNotify) {
    if (!data) {
      throw new Error('read returned no data');
    }

    debug('read data: ' + data.toString('hex'));

    if (this._decryptCipher) {
      var cipherText = data.slice(0x00, 0x10);
      var plainText = this._decryptCipher.update(cipherText);
      plainText.copy(cipherText);

      debug('decrypted data: ' + data.toString('hex'));
    }

    // the notification flag is not being set properly on OSX Yosemite, so just
    // forcing it to true.
    if (process.platform === 'darwin') {
      isNotify = true;
    }

    if (isNotify) {
      this.emit('notification', data);
    }
  }.bind(this));

  // enable notifications on the read characterestic
  debug('enabling notifications on ' + this._readCharacteristic);
  return this._readCharacteristic.notifyAsync(true);
};

LockSession.prototype.execute = function(command) {
  // write the security checksum if on the secure channel
  if (this._isSecure) {
    var checksum = securityChecksum(command);
    command.writeUInt32LE(checksum, 0x0c);
  }

  debug((this._isSecure ? 'secure ' : '') + 'execute command: ' + command.toString('hex'));

  // NOTE: the last two bytes are not encrypted
  // general idea seems to be that if the last byte of the command indicates an offline key offset (is non-zero), the command is "secure" and encrypted with the offline key
  if (this._encryptCipher) {
    var plainText = command.slice(0x00, 0x10);
    var cipherText = this._encryptCipher.update(plainText);
    cipherText.copy(plainText);
    debug('execute command (encrypted): ' + command.toString('hex'));
  }

  // register the notification event listener here, before issuing the write, as the
  // response notification arrives before the write response.
  var waitForNotification = new Promise(function(resolve) {
    this.once('notification', resolve);
  }.bind(this));

  return this._writeCharacteristic.writeAsync(command, false).then(function() {
    debug('write successful, waiting for notification...');
    return waitForNotification;
  }).then(function(data) {
    // perform some basic validation before passing it on
    if (this._isSecure) {
      if (securityChecksum(data) !== data.readUInt32LE(0x0c)) {
        throw new Error("security checksum mismatch");
      }
    } else {
      if (data[0] !== 0xbb && data[0] !== 0xaa) {
        throw new Error("unexpected magic in response");
      }
    }

    return data;
  }.bind(this));
};

module.exports = LockSession;
