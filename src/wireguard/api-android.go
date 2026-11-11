/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
 // TODO: DDG license?

package main

// #cgo LDFLAGS: -llog
// #cgo CFLAGS: -I../netguard/include
// #include <android/log.h>
// #include "platform.h"
import "C"

import (
    "fmt"
    "math"
    "net"
    "os"
    "os/signal"
    "runtime"
    "runtime/debug"
    "strings"
    "sync"
    "unsafe"

    "golang.org/x/sys/unix"
    "golang.zx2c4.com/wireguard/conn"
    "golang.zx2c4.com/wireguard/device"
    "golang.zx2c4.com/wireguard/ipc"
)

type AndroidLogger struct {
    level C.int
    tag   *C.char
}

func cstring(s string) *C.char {
    b, err := unix.BytePtrFromString(s)
    if err != nil {
        b := [1]C.char{}
        return &b[0]
    }
    return (*C.char)(unsafe.Pointer(b))
}

func (l AndroidLogger) Printf(format string, args ...interface{}) {
    if l.level < C.loglevel {
        return
    }
    C.__android_log_write(l.level, l.tag, cstring(fmt.Sprintf(format, args...)))
}

// androidLog writes msg to logcat if level is at or above the log level the app passed to wgTurnOn,
// like log_print does on the C side
func androidLog(level C.int, tag *C.char, msg string) {
    if level < C.loglevel {
        return
    }
    C.__android_log_write(level, tag, cstring(msg))
}

type TunnelHandle struct {
    device *device.Device
    uapi   net.Listener
}

// tunnelHandlesLock guards tunnelHandles: the JNI calls that use it can run on different threads
var tunnelHandles map[int32]TunnelHandle
var tunnelHandlesLock sync.Mutex

func getTunnelHandle(tunnelHandle int32) (TunnelHandle, bool) {
    tunnelHandlesLock.Lock()
    defer tunnelHandlesLock.Unlock()
    handle, ok := tunnelHandles[tunnelHandle]
    return handle, ok
}

func init() {
    tunnelHandles = make(map[int32]TunnelHandle)
    signals := make(chan os.Signal)
    signal.Notify(signals, unix.SIGUSR2)
    go func() {
        buf := make([]byte, os.Getpagesize())
        for {
            select {
            case <-signals:
                n := runtime.Stack(buf, true)
                if n == len(buf) {
                    n--
                }
                buf[n] = 0
                C.__android_log_write(C.ANDROID_LOG_ERROR, cstring("WireGuard/GoBackend/Stacktrace"), (*C.char)(unsafe.Pointer(&buf[0])))
            }
        }
    }()
}

//export wgTurnOn
func wgTurnOn(interfaceName string, tunFd int32, settings string) int32 {
    tag := cstring("WireGuard/GoBackend/" + interfaceName)
    logger := &device.Logger{
        Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
        Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
    }

    tun, name, err := CreateAndroidTUNFromFD(int(tunFd))
    if err != nil {
        unix.Close(int(tunFd))
        logger.Errorf("CreateAndroidTUNFromFD: %v", err)
        return -1
    }

    logger.Verbosef("Attaching to interface %v", name)
    device := device.NewDevice(tun, conn.NewStdNetBind(), logger)

    err = device.IpcSet(settings)
    if err != nil {
        unix.Close(int(tunFd))
        logger.Errorf("IpcSet: %v", err)
        return -1
    }
    device.DisableSomeRoamingForBrokenMobileSemantics()

    var uapi net.Listener

    uapiFile, err := ipc.UAPIOpen(name)
    if err != nil {
        logger.Errorf("UAPIOpen: %v", err)
    } else {
        uapi, err = ipc.UAPIListen(name, uapiFile)
        if err != nil {
            uapiFile.Close()
            logger.Errorf("UAPIListen: %v", err)
        } else {
            go func() {
                for {
                    conn, err := uapi.Accept()
                    if err != nil {
                        return
                    }
                    go device.IpcHandle(conn)
                }
            }()
        }
    }

    err = device.Up()
    if err != nil {
        logger.Errorf("Unable to bring up device: %v", err)
        uapiFile.Close()
        device.Close()
        return -1
    }
    logger.Verbosef("Device started")

    tunnelHandlesLock.Lock()
    var i int32
    for i = 0; i < math.MaxInt32; i++ {
        if _, exists := tunnelHandles[i]; !exists {
            break
        }
    }
    if i == math.MaxInt32 {
        tunnelHandlesLock.Unlock()
        logger.Errorf("Unable to find empty handle")
        uapiFile.Close()
        device.Close()
        return -1
    }
    tunnelHandles[i] = TunnelHandle{device: device, uapi: uapi}
    tunnelHandlesLock.Unlock()
    return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
    tunnelHandlesLock.Lock()
    handle, ok := tunnelHandles[tunnelHandle]
    if ok {
        delete(tunnelHandles, tunnelHandle)
    }
    tunnelHandlesLock.Unlock()
    if !ok {
        return
    }
    if handle.uapi != nil {
        handle.uapi.Close()
    }
    handle.device.Close()
}

//export wgGetSocketV4
func wgGetSocketV4(tunnelHandle int32) int32 {
    handle, ok := getTunnelHandle(tunnelHandle)
    if !ok {
        return -1
    }
    bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
    if bind == nil {
        return -1
    }
    fd, err := bind.PeekLookAtSocketFd4()
    if err != nil {
        return -1
    }
    return int32(fd)
}

//export wgGetSocketV6
func wgGetSocketV6(tunnelHandle int32) int32 {
    handle, ok := getTunnelHandle(tunnelHandle)
    if !ok {
        return -1
    }
    bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
    if bind == nil {
        return -1
    }
    fd, err := bind.PeekLookAtSocketFd6()
    if err != nil {
        return -1
    }
    return int32(fd)
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
    handle, ok := getTunnelHandle(tunnelHandle)
    if !ok {
        return nil
    }
    settings, err := handle.device.IpcGet()
    if err != nil {
        return nil
    }
    return C.CString(settings)
}

//export wgVersion
func wgVersion() *C.char {
    info, ok := debug.ReadBuildInfo()
    if !ok {
        return C.CString("unknown")
    }
    for _, dep := range info.Deps {
        if dep.Path == "golang.zx2c4.com/wireguard" {
            parts := strings.Split(dep.Version, "-")
            if len(parts) == 3 && len(parts[2]) == 12 {
                return C.CString(parts[2][:7])
            }
            return C.CString(dep.Version)
        }
    }
    return C.CString("unknown")
}

func main() {}
