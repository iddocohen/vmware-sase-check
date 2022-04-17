#!/bin/bash -e

# Clean old build files
echo "Starting build..."
echo -n "Cleaning old builds... "
rm -r -f "build"
echo "Done!"

# Create directories
echo -n "Creating directories... "
mkdir "build"
mkdir "build/firefox"
mkdir "build/chromium"
echo "Done!"

# Add warnings
touch "build/DO NOT EDIT THESE FILES DIRECTLY"
touch "build/EDIT THE FILES IN THE SRC DIRECTORY AND RUN BUILD AGAIN"

# Build Firefox
echo -n "Creating Firefox files... "
cp -r "src/." "build/firefox/"
rm -f "build/firefox/manifest-chromium.json"
rm -f "build/firefox/.env-chromium"
mv "build/firefox/manifest-firefox.json" "build/firefox/manifest.json"
mv "build/firefox/.env-firefox" "build/firefox/.env"
echo "Done!"

# Build Chromium
echo -n "Creating Chromium files... "
cp -r "src/." "build/chromium/"
rm -f "build/chromium/manifest-firefox.json"
rm -f "build/chromium/.env-firefox"
mv "build/chromium/manifest-chromium.json" "build/chromium/manifest.json"
mv "build/chromium/.env-chromium" "build/chromium/.env"
echo "Done!"
echo "Build complete!"
