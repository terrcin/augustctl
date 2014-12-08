#!/usr/bin/env node

var Lock = require('./lib/lock');
var noble = require('noble');

var argv = require('yargs')
  .usage('Control an August Smart Lock.\nUsage: $0 [command]')
  .example('$0 lock', 'closes the lock')
  .example('$0 unlock', 'opens the lock')
  .describe('config', 'configuration file (default is $HOME/.config/augustctl.json)')
  .check(function(argv) {
    if (argv._.length !== 1) {
      return 'must specify an operation to perform';
    }

    var op = argv._[0];
    if (typeof Lock.prototype[op] !== 'function') {
      return 'invalid operation: ' + op;
    }
  })
  .argv;

var config = require('./config')(argv.config);

noble.on('stateChange', function(state) {
  if (state === 'poweredOn') {
    noble.startScanning([ Lock.BLE_COMMAND_SERVICE ]);
  } else {
    noble.stopScanning();
  }
});

noble.on('discover', function(peripheral) {
  if (config.uuid === undefined || peripheral.uuid === config.uuid) {
    noble.stopScanning();

    peripheral.on('disconnect', function() {
      process.exit(0);
    });

    var lock = new Lock(
      peripheral,
      config.offlineKey,
      config.offlineKeyOffset
    );
    lock.connect().then(function() {
      var op = argv._[0];
      return lock[op]();
    }).finally(function() {
      return lock.disconnect();
    });
  }
});
