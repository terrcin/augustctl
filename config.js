var fs = require('fs');

function loadConfig(filename) {
  if (!filename) {
    var configDir = process.env.XDG_CONFIG_HOME || (process.env.HOME + '/.config');
    filename = configDir + '/augustctl.json';
  }

  var config = JSON.parse(fs.readFileSync(filename));
  if (!config.offlineKey || !config.offlineKeyOffset) {
    throw new Error("config file must specify offlineKey and offlineKeyOffset");
  }

  return config;
}

module.exports = loadConfig;
