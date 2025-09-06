# WireTap - AOL Protocol Analyzer

A comprehensive network traffic analysis and packet capture tool specifically designed for reverse engineering and analyzing the AOL protocol. This tool provides both interactive GUI and headless server modes for capturing, analyzing, and visualizing AOL network traffic in real-time.

## Screenshot

![WireTap Web Interface](screenshot.png)

*The WireTap web interface showing real-time AOL protocol analysis with session details, protocol insights, and packet visualization.*

## Features

### 🔍 **Packet Capture & Analysis**
- Real-time packet capture from network interfaces
- PCAP and JSONL file processing and analysis
- TCP stream reassembly and Ethernet frame decoding
- Comprehensive AOL protocol dissection with live updates
- Session frame persistence and auto-loading

### 🌐 **Web Interface**
- Modern dark-themed web dashboard
- Live packet capture streaming with Server-Sent Events
- Interactive protocol visualization with syntax highlighting
- Real-time session monitoring and frame inspection
- Proxy controls with configurable listen/destination ports
- Toast notifications for all user feedback
- Automatic reconnection for interrupted live streams

### 🖥️ **Server GUI (Interactive Mode)**
- Native Windows-style interface
- Proxy status with LED-style indicators
- Configurable proxy settings
- Real-time proxy monitoring
- Professional UI with consistent typography

### 🛠️ **Command Line Tools**
- Standalone PCAP/JSONL analysis
- Headless server mode (`--no-gui` flag)
- Protocol token extraction and analysis
- JSON/JSONL export with pretty printing
- Batch processing capabilities

### 📊 **Protocol Intelligence**
- Comprehensive AOL protocol reverse engineering
- Token and atom database with examples
- Historical AOL protocol documentation
- Frame checksum validation (CRC-16 IBM)
- Protocol structure analysis and visualization

## Quick Start

### Prerequisites
- Java 17 or higher
- Maven 3.6+
- Network interface access (for live capture)

### Building
```bash
mvn clean package
```

### Interactive GUI Mode (Default)
```bash
java -jar target/wiretap-1.0.0.jar
```
Starts the server with GUI for interactive proxy control

### Headless Server Mode
```bash
java -jar target/wiretap-1.0.0.jar --no-gui --port 8080
```
Runs server without GUI for remote/headless deployments

### Analyzing PCAP/JSONL Files
```bash
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis
java -jar target/wiretap-1.0.0.jar --pcap session.jsonl --pretty
```

## Usage Examples

### Interactive Mode with Custom Ports
```bash
java -jar target/wiretap-1.0.0.jar --port 8080 --server-port 5190
```
Starts GUI with custom web port and proxy listen port

### Headless Production Server
```bash
java -jar target/wiretap-1.0.0.jar --no-gui --port 8080 --server-port 5191
```
Runs production server without GUI, different ports

### Analyze Existing Capture
```bash
java -jar target/wiretap-1.0.0.jar --pcap mycapture.pcap --pretty --store-full
java -jar target/wiretap-1.0.0.jar --pcap session.jsonl --out analysis
```

### Real-time Sniffing
```bash
java -cp target/classes com.wiretap.tools.RealtimeAolSniffer
```

## Project Structure

```
wiretap/
├── src/main/java/com/wiretap/
│   ├── Main.java                 # Application entry point
│   ├── aol/
│   │   ├── core/                 # Core utilities (CRC, Hex)
│   │   └── extractor/           # AOL-specific decoders
│   ├── extractor/               # General packet extraction
│   │   ├── AolExtractor.java    # Main AOL protocol extractor
│   │   ├── FrameSummary.java    # Frame analysis
│   │   └── io/                  # Output writers
│   ├── tools/                   # Command-line utilities
│   │   ├── PcapReader.java      # PCAP file reader
│   │   ├── ProtocolIndexBuilder.java # Protocol database builder
│   │   └── RealtimeAolSniffer.java   # Live capture tool
│   └── web/                     # Web interface
│       ├── HttpApp.java         # Main web server
│       ├── CaptureLibrary.java  # Session management
│       ├── LiveBus.java        # Real-time updates
│       └── TcpProxyService.java # Proxy functionality
├── protocol/                    # AOL protocol documentation
├── captures/                    # Sample captures and sessions
└── src/main/resources/public/   # Web assets
```

## Web Interface Features

- **Dashboard**: Overview of captured sessions and statistics
- **Live Capture**: Real-time packet streaming and analysis
- **Session Browser**: Navigate through captured sessions
- **Protocol Viewer**: Explore AOL protocol tokens and atoms
- **Proxy Control**: Start/stop TCP proxy for interception

## API Endpoints

### Core Endpoints
- `GET /api/session/frames` - Get current session frames (for web UI prepopulation)
- `GET /api/tokens` - AOL protocol tokens database
- `GET /api/protocols` - Protocol definitions
- `GET /api/atoms` - Protocol atoms database

### Proxy Management
- `POST /api/proxy/start` - Start proxy with custom ports
- `POST /api/proxy/stop` - Stop proxy server
- `GET /api/proxy/status` - Get proxy running status
- `GET /api/proxy-config` - Get proxy configuration
- `POST /api/proxy-config` - Save proxy configuration

### Live Streaming
- `GET /api/live` - Server-sent events for real-time frames
- `POST /api/upload` - Upload and analyze PCAP/JSONL files

### File Processing
- Upload PCAP/JSONL files via web interface
- Real-time processing with toast notifications
- Session persistence across page refreshes

## Development

### Building from Source
```bash
git clone https://github.com/iconidentify/wiretap.git
cd wiretap
mvn clean compile
```

### Running Tests
```bash
mvn test
```

### Creating Distribution
```bash
mvn package
```

## Protocol Documentation

The `protocol/` directory contains extensive documentation about the AOL protocol, including:
- Connection establishment procedures
- Authentication mechanisms
- Data encoding schemes
- Historical protocol evolution
- Token and command references

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Release Notes - v1.0.0

### 🎉 Major Features

#### 🌐 **Modern Web Interface**
- Dark-themed dashboard with professional UI
- Real-time packet streaming with Server-Sent Events
- Interactive protocol visualization with syntax highlighting
- Session frame persistence and auto-loading
- Toast notifications for all user feedback
- Automatic live stream reconnection

#### 🖥️ **Native GUI Application**
- Classic Windows-style interface (mIRC circa 1996 inspired)
- LED-style status indicators for proxy state
- Configurable listen and destination ports
- Real-time proxy monitoring
- Professional typography and consistent styling

#### 🛠️ **Headless Server Mode**
- Production-ready server mode with `--no-gui` flag
- Full web API functionality without GUI overhead
- Perfect for remote deployments and automation
- Graceful shutdown handling

#### 📊 **Advanced Protocol Analysis**
- Comprehensive AOL protocol reverse engineering
- TCP stream reassembly and Ethernet decoding
- Frame checksum validation (CRC-16 IBM)
- Token and atom database with examples
- JSON/JSONL export with pretty printing

### 🚀 **Performance & Reliability**
- High-performance packet processing
- Session persistence across page refreshes
- Automatic reconnection for interrupted streams
- Memory-efficient frame storage (last 1000 frames)
- Thread-safe operations

### 📋 **Usage**

#### Interactive GUI Mode (Default)
```bash
java -jar wiretap-1.0.0.jar
```

#### Headless Server Mode
```bash
java -jar wiretap-1.0.0.jar --no-gui --port 8080
```

#### PCAP Analysis
```bash
java -jar wiretap-1.0.0.jar --pcap capture.pcap --pretty
```

### 🏗️ **Technical Architecture**
- Built with Java 17+ for modern performance
- RESTful web API with comprehensive endpoints
- Real-time streaming with WebSockets/Server-Sent Events
- Modular design for easy extension
- Cross-platform compatibility (macOS, Windows, Linux)

### 📚 **Documentation**
- Comprehensive README with usage examples
- Complete API documentation
- Protocol documentation and examples
- Development setup instructions

---

## Disclaimer

This tool is for educational and research purposes only. Ensure you have proper authorization before capturing or analyzing network traffic.

## Acknowledgments

- Built on reverse engineering work from the AOL protocol community
- Uses various open-source libraries for network analysis
- Inspired by historical AOL protocol documentation efforts
