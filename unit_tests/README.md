# Unit Testing Netguard

## Requirements
An Android x86/64 emulator with no Google Play

## Running Tests
* Build the app or just the `vpn-network-imp` module
* Execute the following:
```
cd android-app/vpn-network/vpn-network-impl/build/intermediates/cmake/debug/obj
adb push x86_64/ /data/
adb shell chmod +x /data/x86_64/test_tcp
adb shell LD_LIBRARY_PATH=/data/x86_64 /data/x86_64/test_tcp
```

__Note__: if you run the last command directly inside an `adb shell`, the output will be color-coded :)