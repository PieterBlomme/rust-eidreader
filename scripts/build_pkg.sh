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

# Code signing configuration
# Set these environment variables before running the script:
#   SIGNING_IDENTITY: Your Developer ID Application certificate (e.g., "Developer ID Application: Your Name (TEAM_ID)")
#   INSTALLER_SIGNING_IDENTITY: Your Developer ID Installer certificate (e.g., "Developer ID Installer: Your Name (TEAM_ID)")
#     If not set, the script will try to auto-detect it from SIGNING_IDENTITY
#   APPLE_ID: Your Apple ID email for notarization
#   APPLE_TEAM_ID: Your Apple Team ID
#   APPLE_APP_SPECIFIC_PASSWORD: App-specific password for notarization (create at appleid.apple.com)
# Or use: xcrun notarytool store-credentials --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID --password YOUR_APP_SPECIFIC_PASSWORD
SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
INSTALLER_SIGNING_IDENTITY="${INSTALLER_SIGNING_IDENTITY:-}"
APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
NOTARIZE="${NOTARIZE:-true}"

# Function to auto-detect installer signing identity from application identity
detect_installer_identity() {
    if [ -n "$INSTALLER_SIGNING_IDENTITY" ]; then
        echo "$INSTALLER_SIGNING_IDENTITY"
        return 0
    fi
    
    if [ -z "$SIGNING_IDENTITY" ]; then
        return 1
    fi
    
    # Try to convert "Developer ID Application" to "Developer ID Installer"
    INSTALLER_IDENTITY=$(echo "$SIGNING_IDENTITY" | sed 's/Developer ID Application/Developer ID Installer/')
    
    # Verify the installer identity exists
    # Note: Don't use -p codesigning filter as installer certs aren't code signing certs
    if security find-identity -v 2>/dev/null | grep -q "$INSTALLER_IDENTITY"; then
        echo "$INSTALLER_IDENTITY"
        return 0
    fi
    
    return 1
}

# Function to check if signing is configured
check_signing_config() {
    if [ -z "$SIGNING_IDENTITY" ]; then
        echo "⚠️  Warning: SIGNING_IDENTITY not set. Package will not be signed."
        echo "   Set SIGNING_IDENTITY environment variable to enable code signing."
        echo "   Example: export SIGNING_IDENTITY='Developer ID Application: Your Name (TEAM_ID)'"
        return 1
    fi
    return 0
}

# Function to check if installer signing is configured
check_installer_signing_config() {
    INSTALLER_ID=$(detect_installer_identity)
    if [ -z "$INSTALLER_ID" ]; then
        if [ -n "$SIGNING_IDENTITY" ]; then
            EXPECTED_INSTALLER=$(echo "$SIGNING_IDENTITY" | sed 's/Developer ID Application/Developer ID Installer/')
            echo "⚠️  Warning: Could not find Developer ID Installer certificate."
            echo "   Looking for: $EXPECTED_INSTALLER"
            echo "   Available Developer ID certificates:"
            security find-identity -v 2>/dev/null | grep "Developer ID" | sed 's/^/     /' || echo "     (none found)"
            echo ""
            echo "   To fix this:"
            echo "   1. Create a 'Developer ID Installer' certificate in Apple Developer Portal"
            echo "   2. Download and install it in your Keychain"
            echo "   3. Or set INSTALLER_SIGNING_IDENTITY if your certificate has a different name"
        else
            echo "⚠️  Warning: Could not find Developer ID Installer certificate."
            echo "   You need a separate 'Developer ID Installer' certificate to sign packages."
            echo "   Set INSTALLER_SIGNING_IDENTITY environment variable, or create the certificate in Apple Developer Portal."
        fi
        return 1
    fi
    return 0
}

# Function to sign a file (uses Application identity for binaries)
sign_file() {
    local file="$1"
    if check_signing_config; then
        echo "Signing: $file"
        codesign --force --deep --sign "$SIGNING_IDENTITY" --options runtime --timestamp "$file"
        codesign --verify --verbose "$file" || { echo "❌ Code signing failed for $file"; exit 1; }
    fi
}

# Clean and build release version for both architectures
echo "Building release version for universal binary..."

# Build for Apple Silicon (aarch64)
echo "Building for Apple Silicon (aarch64)..."
cargo build --release --target aarch64-apple-darwin

# Build for Intel (x86_64)
echo "Building for Intel (x86_64)..."
cargo build --release --target x86_64-apple-darwin

# Create universal binary using lipo
echo "Creating universal binary..."
lipo -create \
    "target/aarch64-apple-darwin/release/EIDReader" \
    "target/x86_64-apple-darwin/release/EIDReader" \
    -output "target/release/${APP_NAME}"

echo "✅ Universal binary created successfully!"

# Verify the universal binary contains both architectures
echo "Verifying universal binary..."
lipo -info "target/release/${APP_NAME}"
file "target/release/${APP_NAME}"

# Create package directory structure
echo "Creating package structure..."
rm -rf "${PACKAGE_DIR}"
mkdir -p "${PACKAGE_DIR}/bin"
mkdir -p "${PACKAGE_DIR}/share/eidreader"
mkdir -p "${SCRIPTS_DIR}"

# Copy the binary
cp "${BUILD_DIR}/${APP_NAME}" "${PACKAGE_DIR}/bin/${APP_NAME}"

# Sign the binary if signing is configured
sign_file "${PACKAGE_DIR}/bin/${APP_NAME}"

# Copy the plist
cp com.example.EIDReader.plist "${PACKAGE_DIR}/share/eidreader/com.example.EIDReader.plist"

# Generate TLS certificates if mkcert is available
if command -v mkcert >/dev/null 2>&1; then
    echo "Generating TLS certificates for localhost..."
    # Install mkcert CA if not already done
    mkcert -install >/dev/null 2>&1 || true
    
    # Generate certificates for the package
    mkcert -key-file "${PACKAGE_DIR}/share/eidreader/localhost-key.pem" \
           -cert-file "${PACKAGE_DIR}/share/eidreader/localhost.pem" \
           localhost 127.0.0.1 ::1
    
    echo "✅ TLS certificates generated and included in package"
else
    echo "⚠️  mkcert not found - package will be built without TLS certificates"
    echo "   Install mkcert with: brew install mkcert nss"
    echo "   Then run: mkcert -install"
fi

# Create a script to install mkcert and nss if needed
cat > "${PACKAGE_DIR}/bin/eidreader-install-deps" << 'EOF'
#!/bin/bash
set -e

echo "Installing mkcert and nss for TLS certificate generation..."

# Check if Homebrew is installed
if ! command -v brew >/dev/null 2>&1; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for this session
    if [[ -f "/opt/homebrew/bin/brew" ]]; then
        export PATH="/opt/homebrew/bin:$PATH"
    elif [[ -f "/usr/local/bin/brew" ]]; then
        export PATH="/usr/local/bin:$PATH"
    fi
fi

# Install mkcert and nss
echo "Installing mkcert and nss..."
brew install mkcert nss

# Install the CA
echo "Installing mkcert CA..."
mkcert -install

echo "✅ Dependencies installed successfully!"
echo "Run 'eidreader-setup-user-service' to set up the service with TLS support."
EOF
chmod +x "${PACKAGE_DIR}/bin/eidreader-install-deps"

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
# Generate local TLS certs using mkcert if available
CERT_DIR="$HOME/.eidreader"
CERT="$CERT_DIR/localhost.pem"
KEY="$CERT_DIR/localhost-key.pem"

# Check if mkcert is available, if not try to install it
if ! command -v mkcert >/dev/null 2>&1; then
  echo "mkcert not found. Attempting to install dependencies..."
  if command -v brew >/dev/null 2>&1; then
    echo "Installing mkcert and nss via Homebrew..."
    brew install mkcert nss
    mkcert -install
  else
    echo "Homebrew not found. Please install mkcert manually:"
    echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    echo "  brew install mkcert nss"
    echo "  mkcert -install"
    echo "Then run this script again."
    exit 1
  fi
fi

mkdir -p "$CERT_DIR"
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Generating localhost TLS certificate (mkcert)..."
  mkcert -install >/dev/null 2>&1 || true
  mkcert -key-file "$KEY" -cert-file "$CERT" localhost 127.0.0.1 ::1
fi
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

# Check for TLS certificates (optional)
if [ -f "/usr/local/share/eidreader/localhost.pem" ] && [ -f "/usr/local/share/eidreader/localhost-key.pem" ]; then
    log "TLS certificates found - will configure HTTPS"
else
    log "No TLS certificates found - will run HTTP only"
fi

# Set permissions
log "Setting permissions..."
chmod 755 "/usr/local/bin/EIDReader" || { log "ERROR: Failed to set permissions on binary"; exit 1; }
chmod 755 "/usr/local/bin/eidreader-setup-user-service" || { log "ERROR: Failed to set permissions on helper script"; exit 1; }
chmod 644 "/usr/local/share/eidreader/com.example.EIDReader.plist" || { log "ERROR: Failed to set permissions on plist"; exit 1; }

# If TLS certs were dropped into system location, set safe perms
if [ -f "/usr/local/share/eidreader/localhost.pem" ] && [ -f "/usr/local/share/eidreader/localhost-key.pem" ]; then
  log "Setting permissions on TLS certs..."
  chmod 644 "/usr/local/share/eidreader/localhost.pem"
  chmod 600 "/usr/local/share/eidreader/localhost-key.pem"
  # Make them readable by all users (needed for LaunchAgent)
  chmod 644 "/usr/local/share/eidreader/localhost-key.pem"
fi

# Set ownership
log "Setting ownership..."
chown root:wheel "/usr/local/bin/EIDReader" || { log "ERROR: Failed to set ownership on binary"; exit 1; }
chown root:wheel "/usr/local/bin/eidreader-setup-user-service" || { log "ERROR: Failed to set ownership on helper script"; exit 1; }
chown root:wheel "/usr/local/share/eidreader/com.example.EIDReader.plist" || { log "ERROR: Failed to set ownership on plist"; exit 1; }

# Ensure ownership for TLS certs if present
if [ -f "/usr/local/share/eidreader/localhost.pem" ] && [ -f "/usr/local/share/eidreader/localhost-key.pem" ]; then
  chown root:wheel "/usr/local/share/eidreader/localhost.pem"
  chown root:wheel "/usr/local/share/eidreader/localhost-key.pem"
fi

log "Installation completed successfully!"
echo "EIDReader has been installed successfully!"
echo ""
echo "To set up the service for your user account, run:"
echo "  eidreader-setup-user-service"
echo ""
echo "If you need to install TLS dependencies (mkcert, nss), run:"
echo "  eidreader-install-deps"
echo ""
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
PKGBUILD_ARGS=(
    --root "${PACKAGE_DIR}"
    --scripts "${SCRIPTS_DIR}"
    --identifier "com.example.${APP_NAME}"
    --version "${VERSION}"
    --install-location "/usr/local"
)

# Add signing if configured (use installer identity for packages)
if check_installer_signing_config; then
    INSTALLER_ID=$(detect_installer_identity)
    echo "Signing package with: $INSTALLER_ID"
    PKGBUILD_ARGS+=(--sign "$INSTALLER_ID")
fi

pkgbuild "${PKGBUILD_ARGS[@]}" "${PACKAGE_DIR}/EIDReader.pkg"

# Build the final package
PRODUCTBUILD_ARGS=(
    --distribution "${PACKAGE_DIR}/distribution.xml"
    --package-path "${PACKAGE_DIR}"
    --version "${VERSION}"
)

# Add signing if configured (use installer identity for packages)
if check_installer_signing_config; then
    INSTALLER_ID=$(detect_installer_identity)
    echo "Signing product archive with: $INSTALLER_ID"
    PRODUCTBUILD_ARGS+=(--sign "$INSTALLER_ID")
fi

productbuild "${PRODUCTBUILD_ARGS[@]}" "${PACKAGE_NAME}.pkg"

echo "✅ Package created: ${PACKAGE_NAME}.pkg"

# Notarize the package if configured
if [ "$NOTARIZE" = "true" ] && check_signing_config; then
    echo "Submitting package for notarization..."
    
    # Determine credential profile
    CREDENTIAL_PROFILE="${NOTARY_CREDENTIAL_PROFILE:-default}"
    
    echo "Using notarytool credential profile: $CREDENTIAL_PROFILE"
    
    # Submit for notarization (will fail with clear error if credentials don't exist)
    echo "Uploading package to Apple for notarization..."
    
    # First, submit without waiting to get the submission ID
    echo "Submitting package (this may take a moment)..."
    SUBMIT_OUTPUT=$(xcrun notarytool submit "${PACKAGE_NAME}.pkg" \
        --keychain-profile "$CREDENTIAL_PROFILE" 2>&1)
    
    SUBMIT_STATUS=$?
    
    if [ $SUBMIT_STATUS -ne 0 ]; then
        echo "❌ Failed to submit package for notarization!"
        echo "$SUBMIT_OUTPUT"
        echo ""
        
        # Check if it's a credential error
        if echo "$SUBMIT_OUTPUT" | grep -qi "credential\|keychain\|profile"; then
            echo "It looks like there's an issue with your notarization credentials."
            echo ""
            echo "To set up credentials, run:"
            echo "  xcrun notarytool store-credentials $CREDENTIAL_PROFILE \\"
            echo "    --apple-id YOUR_APPLE_ID \\"
            echo "    --team-id YOUR_TEAM_ID \\"
            echo "    --password YOUR_APP_SPECIFIC_PASSWORD"
            echo ""
            echo "Or if you've already stored credentials with a different profile name, set:"
            echo "  export NOTARY_CREDENTIAL_PROFILE=your_profile_name"
            echo ""
            echo "You can create an app-specific password at: https://appleid.apple.com"
        fi
        exit 1
    fi
    
    # Extract submission ID
    SUBMISSION_ID=$(echo "$SUBMIT_OUTPUT" | grep -i "id:" | head -1 | sed 's/.*[Ii][Dd]:[[:space:]]*//' | awk '{print $1}')
    
    if [ -z "$SUBMISSION_ID" ]; then
        # Try alternative pattern
        SUBMISSION_ID=$(echo "$SUBMIT_OUTPUT" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1)
    fi
    
    if [ -n "$SUBMISSION_ID" ]; then
        echo "✅ Package submitted for notarization"
        echo "   Submission ID: $SUBMISSION_ID"
        echo ""
        echo "Waiting for notarization to complete (this may take 5-15 minutes)..."
        echo "   (You can check status manually with: xcrun notarytool log $SUBMISSION_ID --keychain-profile $CREDENTIAL_PROFILE)"
        echo ""
    else
        echo "⚠️  Warning: Could not extract submission ID from output:"
        echo "$SUBMIT_OUTPUT"
        echo ""
        echo "Continuing to wait for notarization..."
    fi
    
    # Now wait for completion
    NOTARY_OUTPUT=$(xcrun notarytool wait "$SUBMISSION_ID" \
        --keychain-profile "$CREDENTIAL_PROFILE" \
        --timeout 30m 2>&1)
    
    NOTARY_STATUS=$?
    
    if [ $NOTARY_STATUS -eq 0 ]; then
        echo "✅ Notarization successful!"
        echo "$NOTARY_OUTPUT" | grep -i "status\|accepted\|succeeded" || true
        
        # Staple the notarization ticket
        echo ""
        echo "Stapling notarization ticket..."
        if xcrun stapler staple "${PACKAGE_NAME}.pkg"; then
            # Verify stapling
            if xcrun stapler validate "${PACKAGE_NAME}.pkg"; then
                echo "✅ Notarization ticket stapled successfully!"
            else
                echo "⚠️  Warning: Stapling verification failed, but package may still be valid"
            fi
        else
            echo "⚠️  Warning: Failed to staple notarization ticket"
            echo "   You can staple it later with: xcrun stapler staple ${PACKAGE_NAME}.pkg"
        fi
    else
        echo "❌ Notarization failed or timed out!"
        echo "$NOTARY_OUTPUT"
        echo ""
        
        if [ -n "$SUBMISSION_ID" ]; then
            echo "Check notarization status with:"
            echo "  xcrun notarytool log $SUBMISSION_ID --keychain-profile $CREDENTIAL_PROFILE"
            echo ""
            echo "Or check history:"
            echo "  xcrun notarytool history --keychain-profile $CREDENTIAL_PROFILE"
            echo ""
            echo "If notarization is still in progress, you can staple it later with:"
            echo "  xcrun stapler staple ${PACKAGE_NAME}.pkg"
        fi
        
        # Don't exit with error - package is still built and signed, just not notarized yet
        echo "⚠️  Package is signed but not yet notarized. You can check status and staple later."
    fi
fi

echo ""
echo "📦 Package build complete: ${PACKAGE_NAME}.pkg"
if check_signing_config; then
    echo "✅ Package is signed with: $SIGNING_IDENTITY"
else
    echo "⚠️  Package is NOT signed. Set SIGNING_IDENTITY to enable code signing."
fi 