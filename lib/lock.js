'use strict';

var LockSession = require('./lock_session');

// relevant UUIDs - w/ this library, must be lowercase and without hyphens
const BLE_COMMAND_SERVICE = "bd4ac6100b4511e38ffd0800200c9a66";
const BLE_COMMAND_WRITE_CHARACTERISTIC = "bd4ac6110b4511e38ffd0800200c9a66";
const BLE_COMMAND_READ_CHARACTERISTIC = "bd4ac6120b4511e38ffd0800200c9a66";
const BLE_COMMAND_SECURE_WRITE_CHARACTERISTIC = "bd4ac6130b4511e38ffd0800200c9a66";
const BLE_COMMAND_SECURE_READ_CHARACTERISTIC = "bd4ac6140b4511e38ffd0800200c9a66";

///
// LockCommand
// basically, a zero initialized 18 byte Buffer

function LockCommand() {
  var cmd = new Buffer(0x12);
  cmd.fill(0x00);
  return cmd;
}

///
// Lock object.

function Lock(peripheral, offlineKey, offlineKeyOffset) {
  this._peripheral = peripheral;
  this._offlineKey = offlineKey;
  this._offlineKeyOffset = offlineKeyOffset;

  debug('peripheral: ' + util.inspect(peripheral));
}

Lock.prototype.connect = function() {
  var handshakeKeys;
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
    this._secureSession = new LockSession(
      _.findWhere(characteristics, {uuid: BLE_COMMAND_SECURE_WRITE_CHARACTERISTIC}),
      _.findWhere(characteristics, {uuid: BLE_COMMAND_SECURE_READ_CHARACTERISTIC}),
      true
    );
    this._secureSession.setKey(new Buffer(this._offlineKey, 'hex'));

    // intialize the session
    this._session = new LockSession(
      _.findWhere(characteristics, {uuid: BLE_COMMAND_WRITE_CHARACTERISTIC}),
      _.findWhere(characteristics, {uuid: BLE_COMMAND_READ_CHARACTERISTIC}),
      false
    );

    // start the sessions
    return Promise.join(
      this._secureSession.start(),
      this._session.start()
    );
  }.bind(this)).then(function() {
    // generate handshake keys
    handshakeKeys = crypto.randomBytes(16);

    // send SEC_LOCK_TO_MOBILE_KEY_EXCHANGE
    var cmd = new LockCommand();
    cmd.writeUInt8(0x01, 0x00);    // cmdSecuritySendMobileKeyWithIndex
    handshakeKeys.copy(cmd, 0x04, 0x00, 0x08);
    cmd.writeUInt8(0x0f, 0x10);
    cmd.writeUInt8(this._offlineKeyOffset, 0x11);
    return this._secureSession.execute(cmd);
  }.bind(this)).then(function(response) {
    // setup the session key
    var sessionKey = new Buffer(16);
    handshakeKeys.copy(sessionKey, 0x00, 0x00, 0x08);
    response.copy(sessionKey, 0x08, 0x04, 0x0c);
    this._session.setKey(sessionKey);

    // rekey the secure session as well
    this._secureSession.setKey(sessionKey);

    // send SEC_INITIALIZATION_COMMAND
    var cmd = new LockCommand();
    cmd.writeUInt8(0x03, 0x00);    // cmdSecurityInitializationCommandWithIndex
    handshakeKeys.copy(cmd, 0x04, 0x08, 0x10);
    cmd.writeUInt8(0x0f, 0x10);
    cmd.writeUInt8(this._offlineKeyOffset, 0x11);
    return this._secureSession.execute(cmd);
  }.bind(this));
};

Lock.prototype.lock = function() {
  debug('locking...');

  var cmd = new LockCommand();
  cmd.writeUInt8(0xee, 0x00); // magic
  cmd.writeUInt8(0x0b, 0x01); // cmdLock
  cmd.writeUInt8(0x05, 0x03); // simpleChecksum
  cmd.writeUInt8(0x02, 0x10);
  return this._session.execute(cmd);
};

Lock.prototype.unlock = function() {
  debug('unlocking...');

  var cmd = new LockCommand();
  cmd.writeUInt8(0xee, 0x00); // magic
  cmd.writeUInt8(0x0a, 0x01); // cmdUnlock
  cmd.writeUInt8(0x06, 0x03); // simpleChecksum
  cmd.writeUInt8(0x02, 0x10);
  return this._session.execute(cmd);
};

Lock.prototype.disconnect = function() {
  debug('disconnecting...');

  var cmd = new LockCommand();
  cmd.writeUInt8(0x05, 0x00);  // cmdSecurityTerminate
  cmd.writeUInt8(0x0f, 0x10);
  return this._secureSession.execute(cmd).finally(function() {
    this._peripheral.disconnect();
  }.bind(this));
};

// expose the service uuid
Lock.BLE_COMMAND_SERVICE = BLE_COMMAND_SERVICE;

module.exports = Lock;
