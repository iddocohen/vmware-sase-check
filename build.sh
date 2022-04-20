#!/bin/bash -e

build() {
    NAME=$1
    echo -n "Creating $NAME files... "
    cp -r "src/js/" "build/$NAME/"
    cp -r "src/icon/" "build/$NAME/"
    cp -r "src/css/" "build/$NAME/"
    cp "src/vmchecker.background.html" "build/$NAME/"
    cp "src/vmchecker.tests.html" "build/$NAME/"
    cp "src/.env-$NAME" "build/$NAME/"
    cp "src/manifest-$NAME.json" "build/$NAME/"
    cp "src/package-$NAME.sh" "build/$NAME/"
    mv "build/$NAME/manifest-$NAME.json" "build/$NAME/manifest.json"
    mv "build/$NAME/.env-$NAME" "build/$NAME/.env"
    mv "build/$NAME/package-$NAME.sh" "build/$NAME/package.sh"
    echo "Done!"
}

NOW=$(date +"%T")

# Clean old build files
echo "Starting build..."
echo "Current time : $NOW"
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
build firefox

# Build Edge
build edge

# Build Chromium
build chromium
# Deleting unneeded files for Chrome
rm -f "build/chromium/vmchecker.background.html"

echo "Build complete!"
