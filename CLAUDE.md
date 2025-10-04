# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WireTap is a Java-based network protocol analyzer and packet capture tool designed for reverse engineering and analyzing the AOL protocol. It consists of a JavaFX GUI application, a web interface, and command-line tools for PCAP analysis.

## Build System & Commands

This is a Maven-based Java 17 project using JavaFX and GraalVM for native compilation.

### Common Commands

```bash
# Build the project
mvn clean compile

# Create shaded JAR
mvn clean package

# Run the application (GUI mode)
java -jar target/wiretap-1.0.0.jar

# Run in headless mode
java -jar target/wiretap-1.0.0.jar --no-gui

# Run with dynamic port selection (20000-65535)
java -jar target/wiretap-1.0.0.jar --dynamic-port

# Analyze PCAP files
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis

# Analyze PCAP with full frame storage and pretty printing
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis --store-full --pretty

# Build native macOS executable (requires GraalVM and Maven 3.8.8)
./build-native-macos.sh
```

### Testing
No test framework is configured in this project. Manual testing should be done by running the application.

## Architecture Overview

### Core Components

- **Main.java**: Entry point with command-line argument parsing and application lifecycle management
- **HttpApp**: Web server providing REST API and web interface on port 8080 (default)
- **TcpProxyService**: TCP proxy server for intercepting AOL traffic on port 5190 (default)
- **ServerGUI**: JavaFX-based GUI for desktop application

### Protocol Analysis

The project supports two protocol stacks:
- **AOL Protocol**: Located in `com.wiretap.aol.*` package
- **P3 Protocol**: Located in `com.wiretap.p3.*` package (newer implementation)

Each protocol stack includes:
- **Extractors**: Parse network traffic (`AolExtractor`, `P3Extractor`)
- **Decoders**: Handle link/ethernet/TCP layers (`LinkDecoder`, `EthernetDecoder`, `TcpReassembler`)
- **Core utilities**: CRC calculation and hex utilities

### Data Flow

1. **Input Sources**: PCAP files or live TCP proxy traffic
2. **Protocol Extraction**: Raw packets → structured frames using extractors
3. **Storage**: Frames stored as JSONL format with optional full frame storage
4. **Output**: Web interface, GUI display, or file export

### Key Packages

- `com.wiretap.extractor.*`: Protocol extraction and frame analysis
- `com.wiretap.extractor.io.*`: I/O handling for frames and summaries
- `com.wiretap.web.*`: HTTP server, proxy service, and GUI
- `com.wiretap.tools.*`: Command-line utilities and real-time sniffers
- `com.wiretap.core.*`: Shared utilities (JSON handling)

## Native Compilation

The project uses GluonFX for native compilation with GraalVM.

### Requirements
- GraalVM CE 17 (expected at `/Library/Java/JavaVirtualMachines/graalvm-ce-java17-22.3.1/Contents/Home`)
- Maven 3.8.8 (auto-downloaded by build script if not present)
- macOS ARM64 (Apple Silicon) for macOS builds

### Build Process
The `build-native-macos.sh` script:
1. Downloads Maven 3.8.8 if needed
2. Builds native executable using GluonFX
3. Creates macOS app bundle (WireTap.app)
4. Creates distribution zip (WireTap-macOS.app.zip)
5. Removes quarantine attributes automatically

### Key Files
- `build-native-macos.sh`: Native build script for macOS ARM64
- `src/main/resources/reflect-config.json`: GraalVM reflection configuration
- `src/main/resources/bundles.properties`: GluonFX bundle configuration
- `src/main/resources/icons/icon.icns`: macOS icon (copied to app bundle)

## Data Formats

- **JSONL**: Primary format for session data export/import
- **PCAP**: Standard packet capture format for input
- **JSON**: Configuration and API responses

## Development Notes

- The application auto-detects headless environments and switches to CLI mode
- GUI uses dynamic port selection (20000-65535) when `--dynamic-port` flag is used
- Two protocol implementations exist (AOL and P3) - P3 appears to be the newer version
- The project includes both real-time sniffing and offline PCAP analysis capabilities
- Session data output format: `{basename}.summary.jsonl.gz` for summaries, `{basename}.frames.json.gz` for full frames
- Application version in Info.plist (1.2.4) is separate from Maven version (1.0.0)