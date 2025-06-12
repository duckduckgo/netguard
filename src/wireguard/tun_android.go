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
// #include <stdlib.h>  // For C.free and C string functions
// extern int is_pkt_allowed(char *buffer, int length);
// extern int wg_write_pcap(char *buffer, int length);
// extern int record_malware_block(const char *domain);
import "C"

import (
    "os"
    "unsafe"
    "fmt"

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

func (tunWrapper *NativeTunWrapper) Write(bufs [][]byte, offset int) (int, error) {
    tag := cstring("WireGuard/GoBackend/Write")

        for _, buf := range bufs {
            // Skip uninitialized or empty buffers
            if len(buf) <= offset {
                C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Skipping invalid packet, too short"))
                continue
            }
            switch buf[offset] >> 4 {
            case ipv4.Version:
                if len(buf) < offset+ipv4.HeaderLen {
                    C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Skipping bad IPv4 packet"))
                    continue
                }

                // Check if it's a UDP packet
                protocol := buf[offset+9]
                if protocol == 0x11 { // UDP
                    // Extract UDP ports
                    if len(buf) < offset+ipv4.HeaderLen+8 {
                        C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Skipping short UDP packet"))
                        continue
                    }
                    // Extract the ports (skip IP and check transport layer headers)
                    srcPort := (uint16(buf[offset+ipv4.HeaderLen]) << 8) | uint16(buf[offset+ipv4.HeaderLen+1])
                    dstPort := (uint16(buf[offset+ipv4.HeaderLen+2]) << 8) | uint16(buf[offset+ipv4.HeaderLen+3])

                    if srcPort == 53 || dstPort == 53 {
                        // Extract the DNS data (skip IP and UDP headers)
                        dnsData := buf[offset+ipv4.HeaderLen+8:]

                        // Call the helper function to check if the DNS packet should be blocked
                        shouldBlock, blockedDomain := WasDNSMalwareBlocked(dnsData)
                        if shouldBlock {
                            logMessage := "DNS malware was blocked for domain: " + blockedDomain + " due to 'blocked:m' TXT record"
                            C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring(logMessage))

                            // call back into JVM and let the packet flow normally
                            cBlockedDomain := C.CString(blockedDomain)
                            defer C.free(unsafe.Pointer(cBlockedDomain))
                            C.record_malware_block(cBlockedDomain) // ignore return code
                        }
                    }
                }
            default:
                // Either not an IP packet or unsupported version
                logInvalidPacket(buf, offset, len(buf)-offset, tag)
            }
        }

    pktLen, err :=  tunWrapper.nativeTun.Write(bufs, offset)

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
    // Read packets from the TUN device into bufs.
    n, err := tunWrapper.nativeTun.Read(bufs, sizes, offset)

    tag := cstring("WireGuard/GoBackend/Read")

    // If no packets read, return immediately.
    if n == 0 {
        return n, err
    }

    // Only process the 'n' packets returned by the TUN read.
    for i :=0; i < n; i++ {
        buf := bufs[i]
        // Defensive check: skip if size is 0 or offset is out of bounds.
        if sizes[i] == 0 || len(buf) <= offset {
            sizes[i] = 0
            continue
        }
        // Determine IP version from first nibble (high 4 bits) of first byte.
        switch buf[offset] >> 4 {
            case ipv4.Version:
                // Skip malformed IPv4 packets.
                if len(buf) < ipv4.HeaderLen {
                    C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Skipping bad IPv4 pkt"))
                    sizes[i] = 0
                } else {
                    // Check the IP protocol field (offset + 9 for IPv4).
                    protocol := buf[offset + 9]
                    if protocol == 0x06 {
                        // Use native function to decide whether to allow this packet.
                        allow := int(C.is_pkt_allowed((*C.char)(unsafe.Pointer(&buf[offset])), C.int(sizes[i]+offset)))
                        if allow == 0 {
                            C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("Blocking connection"))
                            sizes[i] = 0 // Set size to 0 to block packet.
                        }
                    }
                }

            // TODO: IPv6
            default:
                // Unknown or unsupported IP version — log details.
                logInvalidPacket(buf, offset, sizes[i], tag)
        }
    }

    // PCAP recording
//     pcap_res := int(C.wg_write_pcap((*C.char)(unsafe.Pointer(&buf[offset])), C.int(pktLen+offset)))
//     if pcap_res < 0 {
//         C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring("PCAP packet not written"))
//     }

    return n, err
}

func logInvalidPacket(buf []byte, offset int, size int, tag *C.char) {
    version := buf[offset] >> 4
    previewLen := min(20, len(buf)-offset)
    headerPreview := buf[offset : offset+previewLen]
    msg := fmt.Sprintf("Invalid IP packet: version=%d, size=%d, firstByte=0x%02x, preview=% x", version, size, buf[offset], headerPreview)
    C.__android_log_write(C.ANDROID_LOG_DEBUG, tag, cstring(msg))
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
