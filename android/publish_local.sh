#!/bin/bash

# Publish netguard library to Maven Local
# This allows testing local changes before publishing to Maven Central

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

echo "📦 Netguard Local Publishing"
echo "============================="
echo ""

# Get current version
CURRENT_VERSION=$(grep VERSION_NAME android/version.properties | cut -d'=' -f2)
print_step "Current version: $CURRENT_VERSION"
echo ""

# Ask if user wants to use a different version
read -p "Use this version? (y/n, or enter new version): " response
if [[ "$response" == "n" ]] || [[ "$response" == "N" ]]; then
    read -p "Enter new version (e.g., 1.11.0-SNAPSHOT-iot): " NEW_VERSION
    if [ -n "$NEW_VERSION" ]; then
        echo "VERSION_NAME=$NEW_VERSION" > android/version.properties
        print_success "Updated version to: $NEW_VERSION"
        CURRENT_VERSION=$NEW_VERSION
    fi
elif [[ "$response" != "y" ]] && [[ "$response" != "Y" ]] && [[ -n "$response" ]]; then
    # User entered a version directly
    echo "VERSION_NAME=$response" > android/version.properties
    print_success "Updated version to: $response"
    CURRENT_VERSION=$response
fi
echo ""

# Clean build
print_step "Cleaning previous builds..."
cd android
./gradlew clean --quiet
print_success "Clean complete"
echo ""

# Build native library
print_step "Building native library with C/C++ changes..."
./gradlew :netguard:assembleDebug --quiet
print_success "Native library built"
echo ""

# Publish to Maven Local
print_step "Publishing to Maven Local..."
./gradlew publishToMavenLocal --quiet
print_success "Published to Maven Local"
echo ""

# Show Maven Local path
MAVEN_LOCAL="$HOME/.m2/repository/com/duckduckgo/netguard/netguard-android/$CURRENT_VERSION"
if [ -d "$MAVEN_LOCAL" ]; then
    print_success "Library available at: $MAVEN_LOCAL"
    echo ""
    echo "📋 Files published:"
    ls -lh "$MAVEN_LOCAL" | tail -n +2
else
    print_warning "Maven Local directory not found at expected location"
fi

echo ""
echo "============================="
echo "✅ Publishing Complete!"
echo "============================="
echo ""
echo "Next steps:"
echo "  1. Update Android app to use Maven Local"
echo "  2. Set version to: $CURRENT_VERSION"
echo "  3. Run: cd /Users/aitor/code/ddg/Android && ./scripts/test_iot_native.sh"
echo ""
