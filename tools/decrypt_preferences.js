'use strict';

var crypto = require('crypto');
var fs = require('fs');

// extract the encoded, encrypted data
var prefs = fs.readFileSync(process.argv[2] || 'LockSettingsPreferences.xml', 'utf8');
var hexEncoded = /[0-9A-F]+(?=\<\/string\>)/.exec(prefs)[0];
var cipherText = new Buffer(hexEncoded, 'hex');

// decrypt
var key = new Buffer('August#@3417r\0\0\0', 'utf8');
var cipher = crypto.createDecipheriv('aes-128-ecb', key, '');
cipher.setAutoPadding(false);
var plaintext = cipher.update(cipherText) + cipher.final();

// remove trailing nulls
plaintext = plaintext.replace(/\0+$/, '');

process.stdout.write(plaintext);
