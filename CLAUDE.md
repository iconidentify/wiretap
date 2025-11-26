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
mvn test                     # Run JUnit tests (41 tests across multiple packages)
mvn clean package            # Create shaded JAR

# Run application (development - JAR)
java -jar target/wiretap-1.0.0.jar                    # GUI mode
java -jar target/wiretap-1.0.0.jar --no-gui           # Headless mode
java -jar target/wiretap-1.0.0.jar --dynamic-port     # Random port 20000-65535

# Run application (production - native binaries)
./wiretap-macos-arm64                                  # macOS GUI mode
./wiretap-macos-arm64 --no-gui --port 3000           # macOS headless mode
wiretap-windows-x64.exe                               # Windows GUI mode

# PCAP analysis
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis --store-full --pretty

# PCAP analysis (native binary)
./wiretap-macos-arm64 --pcap capture.pcap --out analysis

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

### Multi-Connection Architecture

**WireTap supports concurrent TCP connections** with full isolation and tracking:

**Core Components:**
- **`ConnectionRegistry`** (`src/main/java/com/wiretap/web/ConnectionRegistry.java`): Thread-safe registry managing multiple active connections
- **`ConnectionInfo`** (`src/main/java/com/wiretap/web/ConnectionInfo.java`): Metadata for each connection (ID, client IP/port, timestamps, frame count)
- **`TcpProxyService`**: Enhanced to handle multiple simultaneous client connections

**Connection Flow:**
1. **Client Connects**: New TCP connection → `TcpProxyService` generates unique `connectionId`
2. **Registration**: Connection registered in `ConnectionRegistry` with client IP/port
3. **Frame Processing**: Each frame tagged with `connectionId`, `sourceIp`, `sourcePort`
4. **UI Display**: Web interface shows connection pills, allows filtering by connection
5. **Cleanup**: Connection automatically removed when client disconnects

**Key Features:**
- **Unique Connection IDs**: Generated using client IP + port + timestamp
- **Connection Filtering**: Web UI can display frames from specific connections
- **Connection Status**: Real-time display of active vs. historical connections
- **Frame Attribution**: Every frame knows which connection it came from
- **Thread Safety**: All connection operations are thread-safe for concurrent access

**API Endpoints:**
- `GET /api/connections` - Returns all connection metadata
- `GET /api/proxy/status` - Includes active connection count and details

### Package Structure

- **`com.wiretap.core.*`**: Centralized utilities (FrameParser, HexUtil, Crc16Ibm, JsonUtil, WireTapLog)
- **`com.wiretap.extractor.*`**: Protocol extraction (AolExtractor, P3Extractor, FrameSummary)
- **`com.wiretap.extractor.io.*`**: I/O handling (FullFrameStore, SummaryWriter)
- **`com.wiretap.aol.extractor.*`**: AOL-specific decoders (EthernetDecoder, LinkDecoder, TcpReassembler)
- **`com.wiretap.web.*`**: HTTP server (HttpApp), TCP proxy (TcpProxyService), GUI (ServerGUI), WebSocket (LiveBus)
- **`com.wiretap.services.atomforge.*`**: AtomForge FDO decompilation service (AtomForgeService, AtomForgeServiceImpl, AtomForgeConfig, HealthCheckResult)
- **`com.wiretap.tools.*`**: CLI tools (RealtimeAolSniffer, PcapReader, ProtocolIndexBuilder)

**Note**: The P3 package was removed during Phase 5 cleanup. Use AOL decoders for all protocol processing.

### Web Interface Architecture

Single-page application in `src/main/resources/public/index.html`:

- **Vanilla JavaScript** (no frameworks)
- **Server-Sent Events (SSE)** for live frame streaming (`/api/live`)
- **REST API** endpoints:
  - `/api/upload` - PCAP file upload (streaming JSONL response)
  - `/api/proxy/start`, `/api/proxy/stop`, `/api/proxy/status` - TCP proxy control
  - `/api/connections` - Get all connection information (multi-connection support)
  - `/api/session/frames` - Fetch all session frames
  - `/api/live` - Server-Sent Events stream for real-time updates
  - `/api/decompile-frame` - Single frame FDO decompilation (POST `{fullHex: "5A..."}`)
  - `/api/decompile-stream` - Multiple frame decompilation (POST `{frames: ["5A...", "5A..."]}`)
  - `/api/atomforge/health` - Check AtomForge service availability
  - `/api/tokens`, `/api/protocols`, `/api/atoms` - Protocol metadata endpoints

**StreamID Highlighting Feature**: Click streamId pills to highlight all matching frames. Hover shows preview. Implementation uses CSS classes (`.stream-selected`, `.stream-highlighted`, `.stream-hover-preview`) with pure JavaScript event handlers. Only pills are highlighted, not frame containers.

### AtomForge Integration

WireTap integrates with [AtomForge](https://github.com/iconidentify/atom-forge) for on-demand FDO (File Description Object) decompilation.

**Service Architecture**:
- **AtomForgeService**: Interface defining decompilation operations
- **AtomForgeServiceImpl**: Implementation using Java 11+ HttpClient
- **Health Checking**: Periodic background checks with visual status in GUI
- **Endpoints**: `/decompile-jsonl` receives multipart JSONL uploads

**Decompilation Flows**:

1. **Single Frame**: User clicks "Show FDO" → `/api/decompile-frame` → `decompileSingleFrame()` → AtomForge
2. **Stream Decompilation**: User selects streamId → clicks "Decompile Stream" → client filters frames → `/api/decompile-stream` with hex array → `decompileMultipleFrames()` → AtomForge

**Critical Pattern**: Stream decompilation sends frame data **from client to server** because:
- PCAP frames exist only client-side (`framesPcap[]`)
- Live proxy frames exist both places (`framesProxy[]` + server `sessionFrames`)
- Client is source of truth, avoiding server-side session lookups

**Configuration**: AtomForge URL defaults to `http://localhost:8000`, configurable in GUI settings panel.

### Data Model

**`FrameSummary`** is the core data structure containing:

**Core Frame Fields:**
- `dir`: Direction (C->S or S->C)
- `ts`: Timestamp (Unix epoch seconds)
- `len`: Payload length
- `type`, `tx`, `rx`: Frame header bytes
- `token`: 2-byte token (ASCII or hex)
- `streamId`: 2-byte stream identifier (e.g., "0x2a00")
- `crcOk`: Boolean CRC validation result
- `fullHex`: Optional full frame hex dump
- `ref`: SHA-1 hash for deduplication

**Enrichment Fields (Optional):**
- `protocolTag`: Protocol categorization
- `tokenName`: Human-readable token name
- `tokenDesc`: Token description
- `docRef`: Documentation reference
- `atoms`: Parsed frame atoms/components
- `preview`: Human-readable frame preview

**Payload Sampling:**
- `payloadHex`: Truncated hex of payload bytes
- `payloadText`: Printable ASCII sample of payload

**Analysis Flags:**
- `hasError`: Boolean indicating anomaly detection
- `errorCodes`: Comma-separated error codes (e.g., "CRC")

**FDO Decompilation:**
- `fdoSource`: Decompiled FDO source code (cached after first decompilation)

**Connection Tracking (Multi-Connection Support):**
- `connectionId`: Unique identifier for TCP connection
- `sourceIp`: Client IP address
- `sourcePort`: Client port number

### Testing

- **JUnit 5.10.0** framework
- **41 comprehensive tests** across multiple packages:
  - `src/test/java/com/wiretap/core/`
    - `FrameParserTest.java`: 26 tests covering parse() and parseLite()
    - `HexUtilTest.java`: 15 tests for hex utilities
  - `src/test/java/com/wiretap/extractor/`
    - `FrameSummaryConnectionTest.java`: Connection tracking tests
  - `src/test/java/com/wiretap/web/`
    - `ConnectionRegistryTest.java`: Multi-connection registry tests
    - `ConnectionInfoTest.java`: Connection metadata tests

**Test Commands:**
```bash
mvn test                    # Run all tests
mvn test -Dtest=ClassName   # Run single test class
mvn test -Dtest=ClassName#methodName  # Run single test method
```

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

## Development Workflow

### Quick Start for Development
```bash
# 1. Build and run tests
mvn clean compile && mvn test

# 2. Start development server (with verbose logging)
java -jar target/wiretap-1.0.0.jar --verbose --dynamic-port

# 3. Open web interface (URL shown in console output)
open http://localhost:<dynamic-port>
```

### Common Development Tasks

**Single Test Execution:**
```bash
mvn test -Dtest=FrameParserTest                    # Run specific test class
mvn test -Dtest=FrameParserTest#testParseValidFrame # Run single test method
mvn test -Dtest="*Parser*"                         # Run tests matching pattern
```

**Debugging & Logging:**
```bash
# Enable verbose logging for detailed output
java -jar target/wiretap-1.0.0.jar --verbose

# Check WireTapLog output in console for:
# - Frame parsing details
# - TCP connection events
# - AtomForge health checks
# - HTTP request/response logging
```

**Development Testing Workflow:**
```bash
# 1. Make code changes
# 2. Quick compile check
mvn compile

# 3. Run affected tests
mvn test -Dtest=RelevantTest*

# 4. Full test suite before commit
mvn test

# 5. Integration test with PCAP
java -jar target/wiretap-1.0.0.jar --pcap test.pcap --verbose
```

**Troubleshooting Common Issues:**

1. **Build Failures**: Check Java 17 is active: `java -version`
2. **Port Conflicts**: Use `--dynamic-port` or specify different `--port`
3. **AtomForge Issues**: Verify service at `http://localhost:8000/health`
4. **WebSocket Issues**: Check browser DevTools Network tab for SSE connection
5. **Frame Parsing Errors**: Enable `--verbose` and check CRC validation in logs

**Code Modification Guidelines:**
- **Never duplicate frame parsing logic** - use `FrameParser` only
- **Always update tests** when modifying core utilities
- **Run full test suite** before committing
- **Use WireTapLog** for consistent logging across application
- **Follow existing patterns** (vanilla JS for web, thread-safe connection handling)

## Refactoring History

In October 2025, a 5-phase refactoring eliminated critical technical debt:
- Phase 1-4: Consolidated 5 duplicate parsing implementations into `FrameParser`
- Phase 5: Deleted 700+ lines of dead code (P3 package, legacy utilities)
- Result: 239 lines of duplicate code eliminated, 41 unit tests added, zero regressions

See `REFACTORING_REPORT.md` for complete details.
