augustctl
=========

A node.js module to operate an [August Smart Lock](http://www.august.com/), via BLE.

Prerequisties
=============

Same as for [noble](https://github.com/sandeepmistry/noble).

On Linux, you will need [bluez 5](http://www.bluez.org/).

Also tested and working on OSX Yosemite.

Install
=======

	npm install augustctl

Configuration
=============

It's necessary to have an `offlineKey` and corresponding `offlineKeyOffset` that are recognized by your lock.  These can be sourced from an Android phone that is already associated with the lock.  The phone needs to be rooted.

You'll need to copy the `/data/data/com.august.app/shared_prefs/LockSettingsPreferences.xml` file from your phone to your computer. Many file manager apps, or an adb shell, will let you access it, as long as your phone is rooted.

Run this file through the [tools/decrypt_preferences.js](tools/decrypt_preferences.js) script to extract the necessary key.

    mkdir $HOME/.config
    node tools/decrypt_preferences.js LockSettingsPreferences.xml > $HOME/.config/augustctl.json

The decrypted JSON object itself works fine as a configuration file, as long as you only have one lock.

Usage
=====

Assuming you've extracted your offline key and offset into a configuration file, as above, just:

	augustctl unlock
	augustctl lock
