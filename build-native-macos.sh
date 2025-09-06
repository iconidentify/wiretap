#!/bin/bash

# WireTap Native macOS Build Script
# This script builds the native macOS executable using GraalVM and GluonFX
#
# Usage: ./build-native-macos.sh
#
# Requirements:
# - GraalVM CE 17 installed at /Library/Java/JavaVirtualMachines/graalvm-ce-java17-22.3.1/Contents/Home
# - macOS with ARM64 (Apple Silicon)
#
# Note: The script explicitly passes environment variables to Maven/GluonFX
# to ensure compatibility across different terminal environments (including IntelliJ).
#
# Output:
# - target/gluonfx/aarch64-darwin/WireTap (native executable)
# - WireTap.app/ (macOS app bundle)
# - WireTap-macOS.app.zip (distribution zip)
#
# Features:
# - Automatic quarantine removal (xattr -c)
# - Clean builds every time
# - Colored output with progress tracking
# - IntelliJ terminal compatibility

set -e  # Exit on any error

echo "🛠️  WireTap Native macOS Build Script"
echo "====================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GRAALVM_HOME="/Library/Java/JavaVirtualMachines/graalvm-ce-java17-22.3.1/Contents/Home"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if GraalVM is installed
check_graalvm() {
    print_status "Checking GraalVM installation..."

    if [ ! -d "$GRAALVM_HOME" ]; then
        print_error "GraalVM not found at $GRAALVM_HOME"
        print_error "Please install GraalVM CE 17 from https://github.com/graalvm/graalvm-ce-builds/releases"
        print_error "Or update GRAALVM_HOME in this script to match your installation path"
        exit 1
    fi

    export JAVA_HOME="$GRAALVM_HOME"
    export PATH="$JAVA_HOME/bin:$PATH"
    export GRAALVM_HOME="$GRAALVM_HOME"

    java -version
    print_success "GraalVM found and configured"
}

# Setup Maven 3.8.8
setup_maven() {
    print_status "Setting up Maven 3.8.8..."

    MAVEN_DIR="$PROJECT_DIR/apache-maven-3.8.8"

    if [ ! -d "$MAVEN_DIR" ]; then
        print_warning "Maven 3.8.8 not found, downloading..."
        cd "$PROJECT_DIR"
        curl -s https://archive.apache.org/dist/maven/maven-3/3.8.8/binaries/apache-maven-3.8.8-bin.tar.gz | tar xz
        print_success "Maven 3.8.8 downloaded"
    fi

    if [ ! -x "$MAVEN_DIR/bin/mvn" ]; then
        print_error "Maven binary not found or not executable"
        exit 1
    fi

    export PATH="$MAVEN_DIR/bin:$PATH"
    mvn --version
    print_success "Maven 3.8.8 configured"
}

# Clean previous build
clean_build() {
    print_status "Cleaning previous build..."
    cd "$PROJECT_DIR"
    rm -rf target/
    rm -rf WireTap.app/
    rm -f WireTap-macOS.app.zip
    mvn clean
    print_success "Build cleaned"
}

# Build native executable
build_native() {
    print_status "Building native macOS executable..."
    print_warning "This may take several minutes..."

    cd "$PROJECT_DIR"

    # Start timing
    start_time=$(date +%s)

    # Ensure GRAALVM_HOME is set for Maven/GluonFX
    export GRAALVM_HOME="$GRAALVM_HOME"

    # Build with GluonFX - explicitly pass environment variables
    GRAALVM_HOME="$GRAALVM_HOME" JAVA_HOME="$JAVA_HOME" PATH="$PATH" mvn gluonfx:build \
        -Dgluonfx.nativeimage.args="--no-fallback,--allow-incomplete-classpath" \
        -Dgluonfx.macos.codesign=false

    # Calculate build time
    end_time=$(date +%s)
    build_time=$((end_time - start_time))

    print_success "Native build completed in $build_time seconds"
}

# Create macOS app bundle
create_app_bundle() {
    print_status "Creating macOS app bundle..."

    cd "$PROJECT_DIR"

    # Find the executable
    EXECUTABLE_PATH="target/gluonfx/aarch64-darwin/WireTap"

    if [ ! -f "$EXECUTABLE_PATH" ]; then
        print_error "Native executable not found at $EXECUTABLE_PATH"
        exit 1
    fi

    # Create app bundle structure
    mkdir -p WireTap.app/Contents/MacOS
    mkdir -p WireTap.app/Contents/Resources

    # Copy executable
    cp "$EXECUTABLE_PATH" WireTap.app/Contents/MacOS/wiretap
    chmod +x WireTap.app/Contents/MacOS/wiretap

    # Create Info.plist
    cat > WireTap.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>CFBundleExecutable</key><string>wiretap</string>
    <key>CFBundleIdentifier</key><string>com.wiretap.aol</string>
    <key>CFBundleName</key><string>WireTap</string>
    <key>CFBundleVersion</key><string>1.2.4</string>
    <key>CFBundleShortVersionString</key><string>1.2.4</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleSignature</key><string>????</string>
  </dict>
</plist>
EOF

    print_success "App bundle created"
}

# Create distribution zip
create_distribution() {
    print_status "Creating distribution zip..."

    cd "$PROJECT_DIR"

    if [ ! -d "WireTap.app" ]; then
        print_error "App bundle not found"
        exit 1
    fi

    ditto -c -k --sequesterRsrc --keepParent WireTap.app WireTap-macOS.app.zip

    print_success "Distribution zip created: WireTap-macOS.app.zip"
}

# Prepare and list build artifacts
prepare_artifacts() {
    print_status "Preparing build artifacts..."

    cd "$PROJECT_DIR"

    # Remove quarantine attributes for macOS
    if [ -f "target/gluonfx/aarch64-darwin/WireTap" ]; then
        xattr -c "target/gluonfx/aarch64-darwin/WireTap" 2>/dev/null || true
        print_success "Removed quarantine from native executable"
    fi

    if [ -d "WireTap.app" ]; then
        xattr -cr "WireTap.app" 2>/dev/null || true
        print_success "Removed quarantine from app bundle"
    fi

    if [ -f "WireTap-macOS.app.zip" ]; then
        xattr -c "WireTap-macOS.app.zip" 2>/dev/null || true
        print_success "Removed quarantine from distribution zip"
    fi
}

# Show build results
show_results() {
    print_success "Build completed successfully!"
    echo ""
    echo "📦 Build Artifacts Created:"
    echo "  • target/gluonfx/aarch64-darwin/WireTap"
    echo "  • WireTap.app/"
    echo "  • WireTap-macOS.app.zip"
    echo ""
    echo "📊 File Sizes:"
    ls -lh target/gluonfx/aarch64-darwin/WireTap WireTap-macOS.app.zip 2>/dev/null || true
    echo ""
    echo "🚀 Ready to use!"
}

# Main execution
main() {
    echo ""
    check_graalvm
    echo ""
    setup_maven
    echo ""
    clean_build
    echo ""
    build_native
    echo ""
    create_app_bundle
    echo ""
    create_distribution
    echo ""
    prepare_artifacts
    echo ""
    show_results
}

# Run main function
main "$@"
