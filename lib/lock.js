'use strict';

var debug = require('debug')('august:lock');

var Promise = require('bluebird');
var util = require('util');

var LockSession = require('./lock_session');
var SecureLockSession = require('./secure_lock_session');

// relevant UUIDs - w/ this library, must be lowercase and without hyphens
const BLE_COMMAND_SERVICE = "bd4ac6100b4511e38ffd0800200c9a66";
const BLE_COMMAND_WRITE_CHARACTERISTIC = "bd4ac6110b4511e38ffd0800200c9a66";
const BLE_COMMAND_READ_CHARACTERISTIC = "bd4ac6120b4511e38ffd0800200c9a66";
const BLE_COMMAND_SECURE_WRITE_CHARACTERISTIC = "bd4ac6130b4511e38ffd0800200c9a66";
const BLE_COMMAND_SECURE_READ_CHARACTERISTIC = "bd4ac6140b4511e38ffd0800200c9a66";

function Lock(peripheral, offlineKey, offlineKeyOffset) {
  if (!offlineKey) {
    throw new Error('offlineKey must be specified when creating lock');
  }
  if (!offlineKeyOffset) {
    throw new Error('offlineKeyOffset must be specified when creating lock');
  }

  this._peripheral = peripheral;
  this._offlineKey = new Buffer(offlineKey, 'hex');
  this._offlineKeyOffset = offlineKeyOffset;

  debug('peripheral: ' + util.inspect(peripheral));
}

Lock.prototype.connect = function() {
  var handshakeKeys = crypto.randomBytes(16);
  return this._peripheral.connectAsync().then(function() {
    debug('connected.');
    return this._peripheral.discoverServicesAsync([ BLE_COMMAND_SERVICE ]);
  }.bind(this)).then(function(services) {
    debug('services: ' + util.inspect(services));
    if (services.length !== 1) {
      throw new Error("expected exactly one service");
    }
    return services[0].discoverCharacteristicsAsync([]);
  }).then(function(characteristics) {
    debug('characteristics: ' + util.inspect(characteristics));

    // initialize the secure session
    this._secureSession = new SecureLockSession(
      this._peripheral,
      _.findWhere(characteristics, {uuid: BLE_COMMAND_SECURE_WRITE_CHARACTERISTIC}),
      _.findWhere(characteristics, {uuid: BLE_COMMAND_SECURE_READ_CHARACTERISTIC}),
      this._offlineKeyOffset
    );
    this._secureSession.setKey(this._offlineKey);

    // intialize the session
    this._session = new LockSession(
      this._peripheral,
      _.findWhere(characteristics, {uuid: BLE_COMMAND_WRITE_CHARACTERISTIC}),
      _.findWhere(characteristics, {uuid: BLE_COMMAND_READ_CHARACTERISTIC})
    );

    // start the sessions
    return Promise.join(
      this._secureSession.start(),
      this._session.start()
    );
  }.bind(this)).then(function() {
    // send SEC_LOCK_TO_MOBILE_KEY_EXCHANGE
    var cmd = this._secureSession.buildCommand(0x01);
    handshakeKeys.copy(cmd, 0x04, 0x00, 0x08);
    return this._secureSession.execute(cmd);
  }.bind(this)).then(function(response) {
    if (response[0] !== 0x02) {
      throw new Error("unexpected response to SEC_LOCK_TO_MOBILE_KEY_EXCHANGE: " + response.toString('hex'));
    }

    // setup the session key
    var sessionKey = new Buffer(16);
    handshakeKeys.copy(sessionKey, 0x00, 0x00, 0x08);
    response.copy(sessionKey, 0x08, 0x04, 0x0c);
    this._session.setKey(sessionKey);

    // rekey the secure session as well
    this._secureSession.setKey(sessionKey);

    // send SEC_INITIALIZATION_COMMAND
    var cmd = this._secureSession.buildCommand(0x03);
    handshakeKeys.copy(cmd, 0x04, 0x08, 0x10);
    return this._secureSession.execute(cmd);
  }.bind(this)).then(function(response) {
    if (response[0] !== 0x04) {
      throw new Error("unexpected response to SEC_INITIALIZATION_COMMAND: " + response.toString('hex'));
    }
    return true;
  });
};

Lock.prototype.lock = function() {
  debug('locking...');
  var cmd = this._session.buildCommand(0x0b);
  return this._session.execute(cmd);
};

Lock.prototype.unlock = function() {
  debug('unlocking...');
  var cmd = this._session.buildCommand(0x0a);
  return this._session.execute(cmd);
};

Lock.prototype.disconnect = function() {
  debug('disconnecting...');

  var cmd = this._secureSession.buildCommand(0x05);
  cmd.writeUInt8(0x00, 0x11); // zero offline key for security terminate - not sure if necessary
  return this._secureSession.execute(cmd).then(function(response) {
    if (response[0] !== 0x8b) {
      throw new Error("unexpected response to DISCONNECT: " + response.toString('hex'));
    }
    return true;
  }).finally(function() {
    return this._peripheral.disconnectAsync();
  }.bind(this));
};

// expose the service uuid for scanning
Lock.BLE_COMMAND_SERVICE = BLE_COMMAND_SERVICE;

module.exports = Lock;
