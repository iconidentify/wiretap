# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WireTap is a Java-based network protocol analyzer and packet capture tool designed for reverse engineering and analyzing the AOL protocol. It provides real-time traffic analysis, PCAP file processing, and both GUI and headless modes.

## Build System & Commands

Maven-based Java 17 project using JavaFX 17.0.2 and GraalVM for native compilation.

### Essential Commands

```bash
# Build and test
mvn clean compile
mvn test                     # Run JUnit tests (41 tests in com.wiretap.core package)
mvn clean package            # Create shaded JAR

# Run application
java -jar target/wiretap-1.0.0.jar                    # GUI mode
java -jar target/wiretap-1.0.0.jar --no-gui           # Headless mode
java -jar target/wiretap-1.0.0.jar --dynamic-port     # Random port 20000-65535

# PCAP analysis
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis --store-full --pretty

# Native compilation (macOS ARM64)
./build-native-macos.sh      # Requires GraalVM CE 17 and Maven 3.8.8
```

## Critical Architecture Information

### Centralized Frame Parsing (Post-Refactoring)

**IMPORTANT**: As of October 2025, frame parsing logic has been **consolidated** into a single location. All frame parsing **MUST** use the centralized utilities in `com.wiretap.core`:

- **`FrameParser.java`**: Single source of truth for all frame parsing
  - `parse()`: Full analysis with CRC validation, timestamp handling, payload sampling
  - `parseLite()`: Lightweight real-time parsing for live streams
- **`HexUtil.java`**: All hex conversion and formatting utilities
- **`Crc16Ibm.java`**: CRC-16 IBM calculation

**Never duplicate frame parsing logic**. The refactoring eliminated 950+ lines of duplicated code across 5 locations. Any protocol changes must update `FrameParser` only.

### AOL Frame Format

Binary structure: `[5A][CRC 2B][Len 2B][TX][RX][Type][Token 2B][StreamID 2B][Payload...]`

- Byte 0: Magic `0x5A`
- Bytes 1-2: CRC-16 IBM checksum
- Bytes 3-4: Payload length (big-endian)
- Bytes 5-6: TX/RX identifiers
- Byte 7: Frame type
- Bytes 8-9: Token (ASCII or hex)
- Bytes 10-11: StreamID
- Bytes 12+: Payload

### Core Processing Paths

1. **PCAP Upload**: User uploads PCAP → `AolExtractor` → `FrameParser.parse()` → JSONL export
2. **Live Proxy**: TCP traffic on port 5190 → `TcpProxyService` → `FrameParser.parseLite()` → WebSocket → Web UI
3. **Real-time Sniffer**: Network capture → `RealtimeAolSniffer` → `FrameParser.parseLite()` → Live analysis

### Package Structure

- **`com.wiretap.core.*`**: Centralized utilities (FrameParser, HexUtil, Crc16Ibm, JsonUtil)
- **`com.wiretap.extractor.*`**: Protocol extraction (AolExtractor, P3Extractor, FrameSummary)
- **`com.wiretap.extractor.io.*`**: I/O handling (FullFrameStore, SummaryWriter)
- **`com.wiretap.aol.extractor.*`**: AOL-specific decoders (EthernetDecoder, LinkDecoder, TcpReassembler)
- **`com.wiretap.web.*`**: HTTP server (HttpApp), TCP proxy (TcpProxyService), GUI (ServerGUI), WebSocket (LiveBus)
- **`com.wiretap.tools.*`**: CLI tools (RealtimeAolSniffer, PcapReader, ProtocolIndexBuilder)

**Note**: The P3 package was removed during Phase 5 cleanup. Use AOL decoders for all protocol processing.

### Web Interface Architecture

Single-page application in `src/main/resources/public/index.html`:

- **Vanilla JavaScript** (no frameworks)
- **Server-Sent Events (SSE)** for live frame streaming (`/api/live`)
- **REST API** endpoints:
  - `/api/upload` - PCAP file upload (streaming JSONL response)
  - `/api/proxy/start`, `/api/proxy/stop`, `/api/proxy/status`
  - `/api/session/frames` - Fetch all session frames
  - `/api/proxy-config` - Persist proxy configuration

**StreamID Highlighting Feature**: Click streamId pills to highlight all matching frames. Hover shows preview. Implementation uses CSS classes (`.stream-selected`, `.stream-highlighted`, `.stream-hover-preview`) with pure JavaScript event handlers. Only pills are highlighted, not frame containers.

### Data Model

**`FrameSummary`** is the core data structure containing:
- `dir`: Direction (C->S or S->C)
- `ts`: Timestamp (Unix epoch seconds)
- `len`: Payload length
- `type`, `tx`, `rx`: Frame header bytes
- `token`: 2-byte token (ASCII or hex)
- `streamId`: 2-byte stream identifier (e.g., "0x2a00")
- `crcOk`: Boolean CRC validation result
- `fullHex`: Optional full frame hex dump
- `ref`: SHA-1 hash for deduplication

### Testing

- **JUnit 5.10.0** framework
- **41 comprehensive tests** in `src/test/java/com/wiretap/core/`
  - `FrameParserTest.java`: 26 tests covering parse() and parseLite()
  - `HexUtilTest.java`: 15 tests for hex utilities
- All tests must pass before committing: `mvn test`

## Native Compilation

GluonFX + GraalVM for macOS ARM64 builds.

**Prerequisites**:
- GraalVM CE 17 at `/Library/Java/JavaVirtualMachines/graalvm-ce-java17-22.3.1/Contents/Home`
- Maven 3.8.8 (auto-downloaded by build script)
- macOS ARM64 (Apple Silicon)

**Build Process**:
```bash
./build-native-macos.sh      # Creates WireTap.app and WireTap-macOS.app.zip
```

**Key Configuration Files**:
- `src/main/resources/reflect-config.json`: GraalVM reflection configuration
- `src/main/resources/bundles.properties`: GluonFX resource bundles
- `src/main/resources/icons/icon.icns`: macOS app icon

## Data Formats

- **JSONL (JSON Lines)**: Primary export/import format - one JSON object per line
- **PCAP**: Standard packet capture format (Wireshark, tcpdump compatible)
- **Output**: `{basename}.summary.jsonl` for frame summaries, `{basename}.frames.json.gz` for full frames

## Important Development Notes

- **Headless Detection**: Application auto-detects headless environments and switches to CLI mode
- **Dynamic Ports**: GUI uses `--dynamic-port` flag for random port selection (20000-65535)
- **Session Persistence**: Live proxy sessions are stored server-side and can be exported as JSONL
- **Version Discrepancy**: Info.plist shows 1.2.4, Maven POM shows 1.0.0 (intentional)
- **No Framework Lock-in**: Web UI is vanilla JS/CSS for simplicity and maintainability

## Refactoring History

In October 2025, a 5-phase refactoring eliminated critical technical debt:
- Phase 1-4: Consolidated 5 duplicate parsing implementations into `FrameParser`
- Phase 5: Deleted 700+ lines of dead code (P3 package, legacy utilities)
- Result: 239 lines of duplicate code eliminated, 41 unit tests added, zero regressions

See `REFACTORING_REPORT.md` for complete details.
