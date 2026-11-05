#!/bin/zsh
#
# Assembles and codesigns VfsFSKitHost.app with the embedded
# VfsFSKitExtension.appex — no .xcodeproj involved.
#
# Layout produced under build/:
#   VfsFSKitHost.app/Contents/
#     Info.plist
#     MacOS/VfsFSKitHost
#     Extensions/VfsFSKitExtension.appex/Contents/
#       Info.plist
#       MacOS/VfsFSKitExtension
#       Resources/runtime/   <- jlink-minimized Java runtime (JAVA_HOME)
#       Resources/libs/      <- Java classpath jars (incl. vfs-test-*.jar)
#
# Environment:
#   JAVA_HOME             JDK 25 used for jdeps/jlink (required)
#   CODESIGN_IDENTITY     signing identity (default: "-" = ad-hoc)
#   PROVISIONING_PROFILE  .provisionprofile authorizing com.apple.developer.fskit.fsmodule,
#                         embedded into the appex. Required for mounting: the entitlement
#                         is restricted, so ExtensionKit refuses to launch an unprovisioned
#                         extension (extensionKit error 2). Ad-hoc builds compile and
#                         register but cannot mount.
#   SKIP_MAVEN=1          skip the Maven build of the Java side
#   SKIP_SWIFT=1          skip swift build
#
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
FSKIT_DIR="${SCRIPT_DIR:h}"
REPO_ROOT="${FSKIT_DIR:h:h}"
BUILD_DIR="$FSKIT_DIR/build"
CONFIGURATION="${CONFIGURATION:-release}"
IDENTITY="${CODESIGN_IDENTITY:--}"

if [[ -z "${JAVA_HOME:-}" || ! -x "$JAVA_HOME/bin/jlink" ]]; then
	echo "error: JAVA_HOME must point to a JDK providing jdeps and jlink" >&2
	exit 1
fi

# 1. Build the Java side: vfs-test jar + runtime dependencies in target/libs
if [[ "${SKIP_MAVEN:-0}" != "1" ]]; then
	echo "==> Building Java modules"
	(cd "$REPO_ROOT" && ./mvnw -q package -DskipTests -pl vfs-test -am)
fi
VFS_TEST_JAR="$(print -l "$REPO_ROOT"/vfs-test/target/vfs-test-*.jar(N) | grep -vE '(sources|javadoc)\.jar$' | head -1)"
LIBS_DIR="$REPO_ROOT/vfs-test/target/libs"
if [[ ! -f "$VFS_TEST_JAR" || ! -d "$LIBS_DIR" ]]; then
	echo "error: missing $VFS_TEST_JAR or $LIBS_DIR — run the Maven build first" >&2
	exit 1
fi

# 2. Build the Swift targets
if [[ "${SKIP_SWIFT:-0}" != "1" ]]; then
	echo "==> Building Swift targets ($CONFIGURATION)"
	(cd "$FSKIT_DIR" && swift build -c "$CONFIGURATION")
fi
BIN_DIR="$(cd "$FSKIT_DIR" && swift build -c "$CONFIGURATION" --show-bin-path)"

# 3. Assemble the bundle tree
echo "==> Assembling bundle"
APP="$BUILD_DIR/VfsFSKitHost.app"
APPEX="$APP/Contents/Extensions/VfsFSKitExtension.appex"
rm -rf "$BUILD_DIR"
mkdir -p "$APP/Contents/MacOS" "$APPEX/Contents/MacOS" "$APPEX/Contents/Resources/libs"

cp "$FSKIT_DIR/Bundle/VfsFSKitHost-Info.plist" "$APP/Contents/Info.plist"
cp "$BIN_DIR/VfsFSKitHost" "$APP/Contents/MacOS/VfsFSKitHost"
cp "$FSKIT_DIR/Bundle/VfsFSKitExtension-Info.plist" "$APPEX/Contents/Info.plist"
cp "$BIN_DIR/VfsFSKitExtension" "$APPEX/Contents/MacOS/VfsFSKitExtension"

# Bundle any dynamic libraries the Swift build produced (e.g. swift-java)
for dylib in "$BIN_DIR"/*.dylib(N); do
	mkdir -p "$APPEX/Contents/Frameworks"
	cp "$dylib" "$APPEX/Contents/Frameworks/"
	install_name_tool -add_rpath "@executable_path/../Frameworks" "$APPEX/Contents/MacOS/VfsFSKitExtension" 2>/dev/null || true
done

cp "$LIBS_DIR"/*.jar "$APPEX/Contents/Resources/libs/"
cp "$VFS_TEST_JAR" "$APPEX/Contents/Resources/libs/"

# 4. jlink a minimized Java runtime from the real dependency closure.
# All jars load via classpath at runtime, so what matters is the union of JDK
# modules any of them touches (library module names are irrelevant to jlink).
echo "==> Deriving module set with jdeps"
MODULES="$(cd "$APPEX/Contents/Resources/libs" && "$JAVA_HOME/bin/jdeps" --list-deps --ignore-missing-deps --multi-release 25 \
	--module-path . *.jar | sed 's/^ *//' | grep -E '^(java|jdk)\.[a-zA-Z0-9.]+$' | sort -u | paste -sd, -)"
if [[ -z "$MODULES" ]]; then
	echo "error: jdeps produced no module set" >&2
	exit 1
fi
# crypto providers are loaded reflectively and escape jdeps
MODULES="$MODULES,jdk.crypto.ec"
echo "    modules: $MODULES"

echo "==> jlinking runtime"
"$JAVA_HOME/bin/jlink" \
	--add-modules "$MODULES" \
	--strip-debug --no-header-files --no-man-pages --compress=zip-6 \
	--output "$APPEX/Contents/Resources/runtime"

# 5. Optionally embed a provisioning profile. The profile-backed signature must
# carry matching application-identifier/team-identifier entitlements (Xcode adds
# these automatically; here they are derived from the profile).
APPEX_ENTITLEMENTS="$FSKIT_DIR/Bundle/VfsFSKitExtension.entitlements"
if [[ -n "${PROVISIONING_PROFILE:-}" ]]; then
	echo "==> Embedding provisioning profile"
	cp "$PROVISIONING_PROFILE" "$APPEX/Contents/embedded.provisionprofile"
	APP_IDENTIFIER="$(security cms -D -i "$PROVISIONING_PROFILE" | plutil -extract 'Entitlements.com\.apple\.application-identifier' raw -o - -)"
	TEAM_IDENTIFIER="$(security cms -D -i "$PROVISIONING_PROFILE" | plutil -extract 'TeamIdentifier.0' raw -o - -)"
	APPEX_ENTITLEMENTS="$BUILD_DIR/VfsFSKitExtension.entitlements"
	cp "$FSKIT_DIR/Bundle/VfsFSKitExtension.entitlements" "$APPEX_ENTITLEMENTS"
	/usr/libexec/PlistBuddy -c "Add :com.apple.application-identifier string $APP_IDENTIFIER" "$APPEX_ENTITLEMENTS"
	/usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string $TEAM_IDENTIFIER" "$APPEX_ENTITLEMENTS"
	echo "    application-identifier: $APP_IDENTIFIER"
fi

# 6. Codesign inside-out: runtime dylibs, then appex, then app. Hardened
# runtime and notarization are deliberately omitted: local mounts only need a
# valid seal, and Gatekeeper never evaluates unquarantined local builds.
echo "==> Codesigning (identity: $IDENTITY)"
find "$APPEX/Contents/Resources/runtime" -type f \( -name '*.dylib' -o -perm +111 \) | while read -r bin; do
	codesign --force --sign "$IDENTITY" "$bin"
done
for dylib in "$APPEX/Contents/Frameworks"/*.dylib(N); do
	codesign --force --sign "$IDENTITY" "$dylib"
done
codesign --force --sign "$IDENTITY" \
	--entitlements "$APPEX_ENTITLEMENTS" "$APPEX"
codesign --force --sign "$IDENTITY" \
	--entitlements "$FSKIT_DIR/Bundle/VfsFSKitHost.entitlements" "$APP"

echo "==> Done: $APP"
echo "Next steps:"
echo "  ditto '$APP' /Applications/VfsFSKitHost.app"
echo "  codesign --verify --deep --strict /Applications/VfsFSKitHost.app   # must pass, or fskitd won't launch the extension"
echo "  open /Applications/VfsFSKitHost.app   # register the extension with the system"
echo "  Enable it in System Settings > General > Login Items & Extensions > File System Extensions (use the \"By Category\" view)"
echo "  pluginkit -m | grep -i vfs   # verify registration"
echo "  mkdir -p /tmp/vfsmnt && mount -F -t vfsfs <sourceDir> /tmp/vfsmnt"
