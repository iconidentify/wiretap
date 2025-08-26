# WireTap - AOL Protocol Analyzer

A comprehensive network traffic analysis and packet capture tool specifically designed for reverse engineering and analyzing the AOL protocol. This tool provides both command-line and web-based interfaces for capturing, analyzing, and visualizing AOL network traffic.

## Features

### 🔍 **Packet Capture & Analysis**
- Real-time packet capture from network interfaces
- PCAP file processing and analysis
- TCP stream reassembly
- Ethernet frame decoding
- Comprehensive AOL protocol dissection

### 🌐 **Web Interface**
- Modern web-based dashboard for traffic analysis
- Live packet capture streaming
- Interactive protocol visualization
- Session management and replay
- Real-time monitoring with Server-Sent Events

### 🛠️ **Command Line Tools**
- Standalone PCAP analysis
- Protocol token extraction
- Frame summary generation
- JSON/JSONL export capabilities

### 📊 **Protocol Intelligence**
- AOL protocol reverse engineering
- Token and atom database
- Protocol structure analysis
- Historical AOL protocol documentation

## Quick Start

### Prerequisites
- Java 17 or higher
- Maven 3.6+
- Network interface access (for live capture)

### Building
```bash
mvn clean package
```

### Running the Web Interface
```bash
java -jar target/wiretap-1.0.0.jar --serve --port 8080
```
Open http://localhost:8080 in your browser

### Analyzing PCAP Files
```bash
java -jar target/wiretap-1.0.0.jar --pcap capture.pcap --out analysis
```

## Usage Examples

### Start Web Server with Proxy
```bash
java -jar target/wiretap-1.0.0.jar --serve --server-port 5190
```

### Analyze Existing Capture
```bash
java -jar target/wiretap-1.0.0.jar --pcap mycapture.pcap --pretty --store-full
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

- `GET /api/sessions` - List all capture sessions
- `GET /api/sessions/{id}` - Get specific session details
- `GET /api/tokens` - AOL protocol tokens
- `GET /api/protocols` - Protocol definitions
- `GET /api/atoms` - Protocol atoms
- `POST /api/proxy/start` - Start proxy server
- `GET /api/live` - Server-sent events for live updates

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

## Disclaimer

This tool is for educational and research purposes only. Ensure you have proper authorization before capturing or analyzing network traffic.

## Acknowledgments

- Built on reverse engineering work from the AOL protocol community
- Uses various open-source libraries for network analysis
- Inspired by historical AOL protocol documentation efforts
