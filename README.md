Simple tool to work with Xiaomi Sideload

PS: This is my first time coding in C, My C skill sucks, so please don't judge my codes :)

Normal uses:
./xiaomi_adb <cmd> <arg>

Termux uses:
termux-usb -E -e "./xiaomi_adb <cmd> <arg>" -r <usb_device_path>

How to flash sideload OTA
1. ./xiaomi_adb --generate-sign <firmware_path>
2. ./xiaomi_adb --sideload <firmware_path>

While generating sign phone will reboot and you'll need to reboot into Mi-Assistant mode again, that is neccessary because in some cases you can't sideload in device unless you have a press connection in sideload.

make


