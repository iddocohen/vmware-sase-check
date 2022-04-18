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
mkdir "build/edge"
echo "Done!"

# Add warnings
touch "build/DO NOT EDIT THESE FILES DIRECTLY"
touch "build/EDIT THE FILES IN THE SRC DIRECTORY AND RUN BUILD AGAIN"

# Build Firefox
echo -n "Creating Firefox files... "
cp -r "src/." "build/firefox/"
rm -f "build/firefox/manifest-chromium.json"
rm -f "build/firefox/.env-chromium"
rm -f "build/firefox/package-chromium.sh"
mv "build/firefox/manifest-firefox.json" "build/firefox/manifest.json"
mv "build/firefox/.env-firefox" "build/firefox/.env"
mv "build/firefox/package-firefox.sh" "build/firefox/package.sh"
echo "Done!"

# Build Edge
# TODO: Create new files for edge in source
echo -n "Creating Edge files... "
cp -r "src/." "build/edge/"
rm -f "build/edge/manifest-chromium.json"
rm -f "build/edge/.env-chromium"
rm -f "build/edge/package-chromium.sh"
mv "build/edge/manifest-firefox.json" "build/edge/manifest.json"
mv "build/edge/.env-firefox" "build/edge/.env"
mv "build/edge/package-firefox.sh" "build/edge/package.sh"
echo "Done!"


# Build Chromium
echo -n "Creating Chromium files... "
cp -r "src/." "build/chromium/"
rm -f "build/chromium/manifest-firefox.json"
rm -f "build/chromium/.env-firefox"
rm -f "build/chromium/package-firefox.sh"
rm -f "build/chromium/vmchecker.background.html"
mv "build/chromium/manifest-chromium.json" "build/chromium/manifest.json"
mv "build/chromium/.env-chromium" "build/chromium/.env"
mv "build/chromium/package-chromium.sh" "build/chromium/package.sh"
echo "Done!"
echo "Build complete!"
