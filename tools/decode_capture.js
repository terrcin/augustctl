// Decrypts a btsnoop_hci.log from an Android device (enabled in developer options.)

// First use tshark to create a text log from a hci capture:
//   tshark -r btsnoop_hci.log -Y 'btatt.opcode == 0x12 || btatt.opcode == 0x1d' -Tfields -e frame.number -e btatt.opcode -e btatt.handle -e btatt.value >capture.log
// Then, assuming you already have set your offline key:
//   node tools/decode_capture.js capture.log >command.log

'use strict';

var crypto = require('crypto');
var fs = require('fs');

var ZERO_BYTES = new Buffer(16);
ZERO_BYTES.fill(0);

var cryptoKey, sessionKey, txCipherSec, rxCipherSec, txCipher, rxCipher;

function isSecurityChecksumValid(buf) {
  var cs = (0 - (buf.readUInt32LE(0x00) + buf.readUInt32LE(0x04) + buf.readUInt32LE(0x08))) >>> 0;
  return cs === buf.readUInt32LE(0x0c);
}

function isSimpleChecksumValid(buf) {
  var cs = 0;
  for (var i = 0; i < 0x12; i++) {
    cs = (cs + buf[i]) & 0xff;
  }
  return cs === 0;
}

var STATUS = {
   0: 'STM32_FIRMWARE',
   2: 'LOCK_STATE',
   3: 'CURRENT_ANGLE',
   5: 'BATTERY_LEVEL',
   9: 'LOCK_EVENTS_UNREAD',
  10: 'RTC',
  41: 'GIT_HASH'
};

var PARAMETERS = {
   0: 'BACKOFF_TIME_MS',
   1: 'ANIMATION_PERIOD_MS',
   2: 'BATTERY_TYPE',
   3: 'SERIAL_NUMBER_L',
   4: 'SERIAL_NUMBER_H',
   5: 'MANUF_INFO',
   6: 'MANUF_DATE',
   7: 'AUDIO_VOLUME',
   8: 'LED_BRIGHTNESS',
   9: 'CURRENT_KDT',
  10: 'CURRENT_KI',
  11: 'CURRENT_KP',
  12: 'CURRENT_ILIMIT',
  13: 'POS_KDT',
  14: 'POS_KI',
  15: 'POS_KP',
  16: 'POS_ILIMT',
  17: 'RSSI_THRESHOLD',
  18: 'RSSI_FILTER',
  19: 'ACC_THRESHOLD',
  20: 'KNOCK_THRESHOLD',
  21: 'KNOCK_FILTER',
  22: 'STALL_CURRENT_LIMIT',
  23: 'PWM_LIMIT',
  24: 'STALL_POSITION_CW',
  25: 'STALL_POSITION_CCW',
  26: 'TARGET_POSITION_CW',
  27: 'TARGET_POSITION_CCW',
  28: 'BATTERY_SOC_THRESHOLD',
  29: 'MIN_STALL_TIME_MS',
  30: 'BACKOFF_ANGLE',
  31: 'ANGLE_THRESHOLD',
  32: 'ORIENTATION',
  33: 'TEMPERATURE_WARNING',
  34: 'TEMPERATURE_ALARM',
  35: 'ABSOLUTE_CURRENT_LIMIT',
  36: 'MIN_BATTERY_VOTAGE_MV',
  37: 'LOCK_OP_TIMEOUT',
  38: 'BACKOFF_CURRENT_MA',
  39: 'CURRENT_MEASURE_INTERVAL_MS',
  40: 'RELOCK_SEC',
  41: 'UNLOCKED_TOL',
  42: 'LOCKED_TOL',
  43: 'MAX_STALL_CURRENT_ERROR',
  44: 'AUTOCAL_MS',
  45: 'MOTOR_POLARITY',
  46: 'AUTOCAL_ATTEMPTS',
  47: 'PWM_DZONE',
  48: 'NUM_RETRIES',
  49: 'RETRY_TIMER',
  50: 'HLIMIT_ANGLE',
  51: 'SIMULATED',
  52: 'ANGLE_TAU',
  53: 'ACC_VERBOSE',
  54: 'MOTION_VERBOSE',
  55: 'MIN_AWAKE_TIME_MS',
  56: 'AUDIO_ENABLED',
  57: 'BURNIN_TRG',
  58: 'BURNIN_CYCLES',
  59: 'BURNIN_DELAY',
  60: 'BURNIN_CYCLES_DONE',
  61: 'BURNIN_CYCLES_SUCCESS',
  62: 'BURNIN_FAIL_TOL',
  63: 'BURNIN_CAL_SUCCESS',
  64: 'BURNIN_ATTEMPTS',
  65: 'BURNIN_FAILED_ATTEMPTS',
  66: 'BURNIN_TIMESTAMP',
  67: 'BURNIN_NOSLEEP',
  68: 'BURNIN_AUTO_RESTART',
  69: 'BURNIN_INIT_DELAY',
  70: 'BURNIN_IN_PROGRESS',
  71: 'BURNIN_ERRORS',
  72: 'BAT_CRITICAL_TH',
  73: 'BAT_LOW_TH',
  74: 'BAT_MEDIUM_TH',
  75: 'BACKOFF_MIN_MS',
  76: 'BACKOFF_NUM_SAMPLES',
  77: 'AUDIO_INTER_DELAY',
  78: 'POSKP_BACKOFF'
};

// return a crude description of the command
function describe(command) {
  switch (command[0]) {
    case 0x01: return '-> SEC_LOCK_TO_MOBILE_KEY_EXCHANGE';
    case 0x02: return '<- SEC_LOCK_TO_MOBILE_KEY_EXCHANGE';
    case 0x03: return '-> SEC_INITIALIZATION_COMMAND';
    case 0x04: return '<- SEC_INITIALIZATION_COMMAND';
    case 0x05: return '-> DISCONNECT';
    case 0xaa:
    case 0xbb:
    case 0xee:
      var isResponse = command[0] !== 0xee;
      var prefix = isResponse ? '<- ' : '-> ';
      var suffix = '';
      switch (command[1]) {
        case 0x00:
          if (isResponse) {
            var index = command[2];
            switch (index) {
              case 0:
                suffix = JSON.stringify({
                  timestamp: command.readUInt32LE(4),
                  opcode: command[8],
                  currentLockState: command[9],
                  rssi: command.slice(10, 15).toString('hex'),
                  error: command[15]
                });
                break;
              case 1:
                suffix = JSON.stringify({
                  currentAngularPosition: command.readUInt16LE(4),
                  targetAngularPosition: command.readUInt16LE(6),
                  coulombCounter: command.readUInt32LE(8),
                  currentSamples: [
                    command.readUInt16LE(12),
                    command.readUInt16LE(14),
                  ]
                });
                break;
              case 2:
                var samples = [];
                for (var i = 0; i < 6; i++) {
                  samples.push(command.readUInt16LE(4 + i * 2));
                }
                suffix = JSON.stringify({currentSamples: samples});
                break;
              case 3:
                suffix = JSON.stringify({
                  currentSamples: [
                    command.readUInt16LE(4),
                    command.readUInt16LE(6),
                  ],
                  batteryLevel: command.readUInt16LE(8)
                });
                break;
            }
          }
          return prefix + 'GET_LOCK_EVENTS' + suffix;
        case 0x02:
          var status = command.readUInt32LE(0x04);
          if (isResponse) {
            suffix = ' = 0x' + command.readUInt32LE(0x08).toString(16);
          }
          return prefix + 'LOCK_STATUS (0x' + status.toString(16) + ' ' + STATUS[status] + ')' + suffix;
        case 0x04:
          var parameter = command.readUInt32LE(0x04);
          if (isResponse) {
            suffix = ' = 0x' + command.readUInt32LE(0x08).toString(16);
          }
          return prefix + 'GET_PARAM (0x' + parameter.toString(16) + ' ' + PARAMETERS[parameter] + ')' + suffix;
        case 0x0a: return prefix + 'UNLOCK';
        case 0x0b: return prefix + 'LOCK';
      }
      break;
    case 0x8b: return '<- DISCONNECT';
  }
  return null;
}

function decode(frameNumber, opcode, handle, data) {
  var isSecure = (handle === 38 || handle === 41);
  var cipher = (opcode === 18) ? (isSecure ? txCipherSec : txCipher) : (isSecure ? rxCipherSec : rxCipher);

  var ct = data.slice(0x00, 0x10);
  var pt = cipher.update(ct);
  pt.copy(ct);

  var op = (opcode == 18 ? 'WRITE' : 'READ');
  if (isSecure) {
    op = 'S' + op;
    if (!isSecurityChecksumValid(data)) {
      op = op + '*';
    }
  } else {
    if (!isSimpleChecksumValid(data)) {
      op = op + '*';
    }
  }

  console.log([frameNumber, op, data.toString('hex'), describe(data)].join('\t'));

  if (isSecure) {
    switch (data[0]) {
      case 0x01:
        sessionKey = new Buffer(0x10);
        data.copy(sessionKey, 0x00, 0x04, 0x0c);
        break;
      case 0x02:
        data.copy(sessionKey, 0x08, 0x04, 0x0c);
        txCipher = crypto.createDecipheriv('aes-128-cbc', sessionKey, ZERO_BYTES); txCipher.setAutoPadding(false);
        rxCipher = crypto.createDecipheriv('aes-128-cbc', sessionKey, ZERO_BYTES); rxCipher.setAutoPadding(false);
        txCipherSec = crypto.createDecipheriv('aes-128-ecb', sessionKey, ''); txCipherSec.setAutoPadding(false);
        rxCipherSec = crypto.createDecipheriv('aes-128-ecb', sessionKey, ''); rxCipherSec.setAutoPadding(false);
        break;
    }
  }
}

function decodeLog(offlineKey, filename) {
  cryptoKey = new Buffer(offlineKey, 'hex');
  txCipherSec = crypto.createDecipheriv('aes-128-ecb', cryptoKey, ''); txCipherSec.setAutoPadding(false);
  rxCipherSec = crypto.createDecipheriv('aes-128-ecb', cryptoKey, ''); rxCipherSec.setAutoPadding(false);

  var records = fs.readFileSync(filename, 'ascii').split(/\n/);
  records.forEach(function(record) {
    var fields = record.split(/\t/);
    if (fields.length !== 4) {
      return;
    }
    var buf = new Buffer(fields[3].replace(/:/g, ''), 'hex');
    if (buf.length === 18) {
      decode(+fields[0], +fields[1], +fields[2], buf);
    }
  });
}

var config = require(process.env.AUGUSTCTL_CONFIG || '../config.json');
decodeLog(config.offlineKey, process.argv[2]);
