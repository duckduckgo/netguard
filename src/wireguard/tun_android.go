/*
 * Copyright (c) 2022 DuckDuckGo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

/*
Implementation of the TUN device interface for Android (wraps linux one)
 */


// #include <android/log.h>
// extern int is_pkt_allowed(char *buffer, int length);
// extern int wg_write_pcap(char *buffer, int length);
import "C"

import (
    "os"
    "unsafe"

    "golang.org/x/net/ipv4"
    "golang.zx2c4.com/wireguard/tun"
)

type NativeTunWrapper struct {
    nativeTun tun.Device
}

func (tunWrapper *NativeTunWrapper) File() *os.File {
    return tunWrapper.nativeTun.File()
}

func (tunWrapper *NativeTunWrapper) MTU() (int, error) {
    return tunWrapper.nativeTun.MTU()
}

func (tunWrapper *NativeTunWrapper) Name() (string, error) {
    return tunWrapper.nativeTun.Name()
}

func (tunWrapper *NativeTunWrapper) Write(buf [][]byte, offset int) (int, error) {
    pktLen, err :=  tunWrapper.nativeTun.Write(buf, offset)

//     tag := cstring("WireGuard/GoBackend/Write")

    // PCAP recording
//     pcap_res := int(C.wg_write_pcap((*C.char)(unsafe.Pointer(&buf[offset])), C.int(pktLen+offset)))
//     if pcap_res < 0 {
//         C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("PCAP packet not written"))
//     }

    return pktLen, err
}

func (tunWrapper *NativeTunWrapper) Flush() error {
    return nil
}

// tunWrapper.nativeTun.Read() Reads one or more packets from the Device (without any additional headers).
// On a successful read it returns the number of packets read, and sets
// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
// A nonzero offset can be used to instruct the Device on where to begin
// reading into each element of the bufs slice.
func (tunWrapper *NativeTunWrapper) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
    n, err := tunWrapper.nativeTun.Read(bufs, sizes, offset)

    tag := cstring("WireGuard/GoBackend/Read")

    if n == 0 {
        return n, err
    }

    for i, buf := range bufs {
        switch buf[offset] >> 4 {
            case ipv4.Version:
                if len(buf) < ipv4.HeaderLen {
                    C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Skipping bad IPv4 pkt"))
                    sizes[i] = 0
                } else {
                    // Check if TCP
                    protocol := buf[offset + 9]
                    if protocol == 0x06 {
                        // Skip checking with AppTP since for now we only check TCP connections
                        allow := int(C.is_pkt_allowed((*C.char)(unsafe.Pointer(&buf[offset])), C.int(sizes[i]+offset)))
                        if allow == 0 {
                            // Returning 0 blocks the connection since we will not forward this packet
                            C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Blocking connection"))
                            sizes[i] = 0
                        }
                    }
                }

            // TODO: IPv6
            default:
                C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Invalid IP"))
        }
    }

    // PCAP recording
//     pcap_res := int(C.wg_write_pcap((*C.char)(unsafe.Pointer(&buf[offset])), C.int(pktLen+offset)))
//     if pcap_res < 0 {
//         C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("PCAP packet not written"))
//     }

    return n, err
}

func (tunWrapper *NativeTunWrapper) Events() <-chan tun.Event {
    return tunWrapper.nativeTun.Events()
}

func (tunWrapper *NativeTunWrapper) Close() error {
    return tunWrapper.nativeTun.Close()
}

func (tunWrapper *NativeTunWrapper) BatchSize() int {
    return tunWrapper.nativeTun.BatchSize()
}

func CreateAndroidTUNFromFD(fd int) (tun.Device, string, error) {
    nativeTun, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
    if err != nil {
        return nil, name, err
    }

    device := &NativeTunWrapper{
        nativeTun: nativeTun,
    }

    return device, name, err
}
