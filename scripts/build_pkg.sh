#!/bin/bash

# Exit on error
set -e

# Configuration
APP_NAME="EIDReader"
VERSION=$(grep '^version = ' Cargo.toml | head -n1 | cut -d'"' -f2 | tr -d '\n')
PACKAGE_NAME="${APP_NAME}-${VERSION}"
BUILD_DIR="target/release"
PACKAGE_DIR="package"
SCRIPTS_DIR="${PACKAGE_DIR}/scripts"

# Clean and build release version
echo "Building release version..."
cargo build --release

# Create package directory structure
echo "Creating package structure..."
rm -rf "${PACKAGE_DIR}"
mkdir -p "${PACKAGE_DIR}/bin"
mkdir -p "${PACKAGE_DIR}/share/eidreader"
mkdir -p "${SCRIPTS_DIR}"

# Copy the binary
cp "${BUILD_DIR}/${APP_NAME}" "${PACKAGE_DIR}/bin/${APP_NAME}"

# Copy the plist
cp com.example.EIDReader.plist "${PACKAGE_DIR}/share/eidreader/com.example.EIDReader.plist"

# Create the helper script
echo "Creating helper script..."
cat > "${PACKAGE_DIR}/bin/eidreader-setup-user-service" << 'EOF'
#!/bin/bash
set -e

PLIST_SRC="/usr/local/share/eidreader/com.example.EIDReader.plist"
PLIST_DEST="$HOME/Library/LaunchAgents/com.example.EIDReader.plist"

echo "Setting up EIDReader service for your user account..."
mkdir -p "$HOME/Library/LaunchAgents"
cp "$PLIST_SRC" "$PLIST_DEST"
launchctl unload "$PLIST_DEST" 2>/dev/null || true
launchctl load "$PLIST_DEST"
echo "✅ EIDReader service installed and started successfully!"
echo "The service will automatically start when you log in."
EOF
chmod +x "${PACKAGE_DIR}/bin/eidreader-setup-user-service"

# Create postinstall script
cat > "${SCRIPTS_DIR}/postinstall" << 'EOF'
#!/bin/bash

# Enable error logging and exit on error
set -ex

# Create log file
LOG_FILE="/tmp/eidreader_install.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

echo "Starting postinstall script at $(date)" >&2

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Function to check if a file exists
check_file() {
    if [ ! -f "$1" ]; then
        log "ERROR: File not found: $1"
        log "Directory contents:"
        ls -la "$(dirname "$1")" >&2
        return 1
    fi
    return 0
}

# Print environment information
log "Environment information:"
log "Current user: $(whoami)"
log "Current directory: $(pwd)"
log "PATH: $PATH"

# List contents of /usr/local/bin
log "Contents of /usr/local/bin:"
ls -la /usr/local/bin >&2

# List contents of /usr/local/share/eidreader
log "Contents of /usr/local/share/eidreader:"
ls -la /usr/local/share/eidreader >&2

# Check if files exist before setting permissions
log "Checking if required files exist..."
check_file "/usr/local/bin/EIDReader" || { log "ERROR: Binary not found"; exit 1; }
check_file "/usr/local/bin/eidreader-setup-user-service" || { log "ERROR: Helper script not found"; exit 1; }
check_file "/usr/local/share/eidreader/com.example.EIDReader.plist" || { log "ERROR: Plist not found"; exit 1; }

# Set permissions
log "Setting permissions..."
chmod 755 "/usr/local/bin/EIDReader" || { log "ERROR: Failed to set permissions on binary"; exit 1; }
chmod 755 "/usr/local/bin/eidreader-setup-user-service" || { log "ERROR: Failed to set permissions on helper script"; exit 1; }
chmod 644 "/usr/local/share/eidreader/com.example.EIDReader.plist" || { log "ERROR: Failed to set permissions on plist"; exit 1; }

# Set ownership
log "Setting ownership..."
chown root:wheel "/usr/local/bin/EIDReader" || { log "ERROR: Failed to set ownership on binary"; exit 1; }
chown root:wheel "/usr/local/bin/eidreader-setup-user-service" || { log "ERROR: Failed to set ownership on helper script"; exit 1; }
chown root:wheel "/usr/local/share/eidreader/com.example.EIDReader.plist" || { log "ERROR: Failed to set ownership on plist"; exit 1; }

log "Installation completed successfully!"
echo "EIDReader has been installed successfully!"
echo "To set up the service for your user account, run:"
echo "  eidreader-setup-user-service"
echo "Installation log available at: $LOG_FILE"
EOF
chmod +x "${SCRIPTS_DIR}/postinstall"

# Create distribution.xml
cat > "${PACKAGE_DIR}/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-script minSpecVersion="1.000000">
    <title>EIDReader</title>
    <organization>com.example</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="10.13"/>
        </allowed-os-versions>
    </volume-check>
    <installation-check script="pm_install_check();"/>
    <script>
        function pm_install_check() {
            if(!(system.compareVersions(system.version.ProductVersion,'10.13.0') >= 0)) {
                my.result.title = 'Unable to install';
                my.result.message = 'EIDReader requires macOS 10.13 or later.';
                my.result.type = 'Fatal';
                return false;
            }
            return true;
        }
    </script>
    <choices-outline>
        <line choice="com.example.EIDReader.choice"/>
    </choices-outline>
    <choice id="com.example.EIDReader.choice" title="EIDReader">
        <pkg-ref id="com.example.EIDReader.pkg"/>
    </choice>
    <pkg-ref id="com.example.EIDReader.pkg" auth="Root">#EIDReader.pkg</pkg-ref>
</installer-script>
EOF

# Build the component package
pkgbuild --root "${PACKAGE_DIR}" \
         --scripts "${SCRIPTS_DIR}" \
         --identifier "com.example.${APP_NAME}" \
         --version "${VERSION}" \
         --install-location "/usr/local" \
         "${PACKAGE_DIR}/EIDReader.pkg"

# Build the final package
productbuild --distribution "${PACKAGE_DIR}/distribution.xml" \
             --package-path "${PACKAGE_DIR}" \
             --version "${VERSION}" \
             "${PACKAGE_NAME}.pkg"

echo "Package created: ${PACKAGE_NAME}.pkg" 