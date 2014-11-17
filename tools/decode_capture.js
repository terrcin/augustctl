// Decrypts a btsnoop_hci.log from an Android device (enabled in developer options.)

// First use tshark to create a text log from a hci capture:
//   tshark -r btsnoop_hci.log -Y 'btatt.opcode == 0x12 || btatt.opcode == 0x1d' -Tfields -e frame.number -e btatt.opcode -e btatt.handle -e btatt.value >capture.log
// Then, assuming you already have a config file with your offline key, decrypt it:
//   node tools/decode_capture.js capture.log >command.log

var crypto = require('crypto');
var fs = require('fs');

var ZERO_BYTES = new Buffer(16);
ZERO_BYTES.fill(0);

var cryptoKey, sessionKey, txCipherSec, rxCipherSec, txCipher, rxCipher;

function isSecurityChecksumValid(buf) {
  var cs = (0 - (buf.readUInt32LE(0x00) + buf.readUInt32LE(0x04) + buf.readUInt32LE(0x08))) >>> 0;
  return cs === buf.readUInt32LE(0x0c);
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
  }

  console.log([frameNumber, op, data.toString('hex')].join('\t'));

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

var config = require('../config')();
decodeLog(config.offlineKey, process.argv[2]);
