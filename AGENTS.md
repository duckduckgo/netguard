# AGENTS.md

This file provides guidance to coding agents working with code in this repository.

## Project Overview

This is Netguard, a fork of NetGuard's native code used in DuckDuckGo's App Tracking Protection and Network Protection features. The repository contains:

1. **Native C Library** (`src/netguard/`) - Core VPN packet filtering/routing implementation
2. **WireGuard Integration** (`src/wireguard/`) - Modified libwg-go library from WireGuard Android
3. **Android Library** (`android/`) - Production Android library that wraps the native code
4. **Android Test App** (`android-test/`) - Testing application for the native code

The API is not stable and may change as needed. This is production code used in DuckDuckGo products.

## Architecture

### Native Layer (C)
The core networking logic is implemented in C under `src/netguard/`:

- **netguard.c/h** - Main JNI interface, packet creation, and event loop
- **session.c/h** - Session management for TCP, UDP, and ICMP connections
- **tcp.c, udp.c, icmp.c** - Protocol-specific packet handling
- **ip.c** - IP packet processing (IPv4/IPv6)
- **tls.c, tls_parser.c** - TLS SNI inspection for domain-based blocking
- **dns.c** - DNS response parsing for blocking decisions
- **tun.c** - TUN device interaction for packet capture/injection
- **socks5.c** - SOCKS5 proxy support
- **uid_mapping.c** - Android UID-based traffic attribution
- **memory.c, util.c, fd_util.c** - Utilities and memory management
- **android.c** - Android-specific platform code

The native code uses epoll for event handling and maintains separate session tracking for each protocol. It inspects TLS SNI headers and DNS responses to support domain-based blocking.

### JNI Bridge
The native code communicates with Android through JNI, using model classes in `com.duckduckgo.vpn.network.impl.models`:
- `Packet` - Network packet metadata
- `Allowed` - Address allowlist information
- `ResourceRecord` - DNS resource records
- `Usage` - Network traffic accounting

### WireGuard Integration
The `src/wireguard/` directory contains a modified copy of WireGuard's libwg-go library, built as a separate shared library (`libwg-go.so`) alongside the main netguard library.

## Build Commands

### Android Library (Primary)
From the `android/` directory:

```bash
./gradlew build                # Build all variants
./gradlew assembleDebug        # Build debug AAR
./gradlew assembleRelease      # Build release AAR
./gradlew clean               # Clean build artifacts
```

On Apple Silicon Macs the Gradle native build fails (it runs x86 ninja under Rosetta). Build the native libraries with the SDK's cmake directly instead, as in the `verify-netguard` skill (`.claude/skills/verify-netguard/SKILL.md`).

### Testing
```bash
./gradlew test                      # Run all unit tests
./gradlew testDebugUnitTest         # Run debug unit tests
./gradlew connectedDebugAndroidTest # Run instrumented tests on device
./gradlew lint                      # Run lint checks
```

### Native Code
The native code is built via CMake during the Gradle build. CMake configuration is in `android/netguard/src/main/cpp/CMakeLists.txt`.

For standalone native tests:
```bash
cd src/test
make          # Build test_tls, test_tls_split, test_tls_fuzz, test_tcp_window, test_packet_headers, test_dns_session
./test_tls    # Run each test executable
make clean    # Clean test artifacts
```

The WireGuard library is built via its own Makefile during the CMake build process, invoked as a custom target.

### Keeping these docs current
This file and the skills in `.claude/skills` describe the repo. If a step in them fails or is wrong because the repo changed, fix the doc in the same commit as the code change, and say so in the PR. CI runs `node tools/check-docs/check-docs.js`, which fails when a file, link, C name, native test or log message the docs mention no longer exists.

### Verifying changes
Unit tests are not enough. Before calling a change to `src/netguard` or `src/wireguard` done, verify it on a device with the `verify-netguard` skill (`.claude/skills/verify-netguard/SKILL.md`): the change built into the app, compared with `main` on the same phone.

To review someone else's PR, use the `review-netguard` skill (`.claude/skills/review-netguard/SKILL.md`): it proves each finding with a run, verifies on a device, and drafts a PASS / PASS+NOTES / FAIL / INCOMPLETE verdict comment.

## Development Notes

- **NDK Version**: 21.4.7075529
- **Compile SDK**: 32
- **Min SDK**: 23 (Android 6.0)
- **Target SDK**: 32
- **Build System**: Gradle with CMake for native code
- **16KB Page Size Support**: Both native libraries are built with `-Wl,-z,max-page-size=16384` and `-Wl,-z,common-page-size=16384` for compatibility with newer Android devices

### Important Patterns

1. **Session Management**: The code maintains session state for each connection in linked lists, tracked via epoll file descriptors.

2. **Packet Flow**: Packets flow through: TUN device → IP layer → protocol handlers (TCP/UDP/ICMP) → optional inspection (TLS SNI, DNS) → routing decision → socket forwarding or blocking.

3. **JNI Callbacks**: The native code calls back into Java for policy decisions (domain blocking, UID queries, usage accounting) via JNI method invocations.

4. **Memory Tracking**: Custom memory allocation tracking (`memory.c`) for debugging leaks in native code.

## Publishing

### Maven Local (Development)
For local development and testing in other projects, you can publish to your local Maven repository.

From the `android/` directory:

```bash
./publish_local.sh              # Build and publish to Maven Local (recommended)
# OR
./gradlew publishToMavenLocal   # Direct Gradle command
```

The library will be published as `com.duckduckgo.netguard:netguard-android:<version>` to your local Maven repository (typically `~/.m2/repository/`).

To use the local version in another project:
```gradle
repositories {
    mavenLocal()  // Add this before other repositories
    // ... other repositories
}

dependencies {
    implementation 'com.duckduckgo.netguard:netguard-android:<version>'
}
```

### Maven Central (Production)
The library is published to Maven Central as `com.duckduckgo.netguard:netguard-android`. The version comes from git tags: pushing an `X.Y.Z` tag on `main` releases it, and `main` publishes the next minor version as a snapshot. See `android/RELEASING.md` for release procedures.
