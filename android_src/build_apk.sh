#!/bin/bash
# Build CF IP Keeper APK using ONLY local Android SDK tools (no Gradle, no internet).
set -e
SDK="C:/Users/arash/AppData/Local/Android/Sdk"
JBR="C:/Program Files/Android/Android Studio/jbr"
SRC="C:/Users/arash/cf-ip-keeper/android/java"
RES="C:/Users/arash/cf-ip-keeper/android/appres"
OUT="C:/Users/arash/cf-ip-keeper/android/build"
APKDIR="C:/Users/arash/cf-ip-keeper/android"
PLATFORM="$SDK/platforms/android-37.0/android.jar"
BT="$SDK/build-tools/36.0.0"

rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex" "$OUT/apk"

echo "== 1. aapt2 link =="
if [ -d "$(cygpath -u "$RES/res")" ]; then
  "$BT/aapt2.exe" compile --dir "$RES/res" -o "$OUT/res.zip"
  "$BT/aapt2.exe" link -o "$OUT/apk/base.apk" \
    -I "$PLATFORM" --manifest "$RES/AndroidManifest.xml" \
    --min-sdk-version 26 --target-sdk-version 34 \
    --version-code 1 --version-name "1.0" \
    "$OUT/res.zip"
else
  "$BT/aapt2.exe" link -o "$OUT/apk/base.apk" \
    -I "$PLATFORM" --manifest "$RES/AndroidManifest.xml" \
    --min-sdk-version 26 --target-sdk-version 34 \
    --version-code 1 --version-name "1.0"
fi

echo "== 2. javac =="
SRCLIST=$(find "$(cygpath -u "$SRC")" -name "*.java" | while read -r f; do cygpath -w "$f"; done | tr '\n' ' ')
"$JBR/bin/javac.exe" -source 11 -target 11 \
  -classpath "$PLATFORM" -d "$OUT/classes" \
  $SRCLIST

echo "== 3. d8 dex =="
CLASSLIST=$(find "$(cygpath -u "$OUT/classes")" -name "*.class" | while read -r f; do cygpath -w "$f"; done | tr '\n' ' ')
"$BT/d8.bat" --release --lib "$PLATFORM" --output "$OUT/dex" $CLASSLIST

echo "== 4. add classes.dex into apk =="
cd "$(cygpath -u "$OUT/dex")"
"$BT/aapt.exe" add "$(cygpath -w "$OUT/apk/base.apk")" classes.dex

echo "== 5. zipalign =="
"$BT/zipalign.exe" -f 4 "$OUT/apk/base.apk" "$OUT/apk/aligned.apk"

echo "== 6. sign =="
KS="$(cygpath -u "$OUT/debug.keystore")"
if [ ! -f "$KS" ]; then
  "$JBR/bin/keytool.exe" -genkeypair -keystore "$OUT/debug.keystore" -alias cfk \
    -storepass android -keypass android -dname "CN=CF IP Keeper Debug" \
    -keyalg RSA -keysize 2048 -validity 10000 >/dev/null 2>&1
fi
"$BT/apksigner.bat" sign --ks "$OUT/debug.keystore" --ks-pass pass:android \
  --out "$APKDIR/CF-IP-Keeper-debug.apk" "$OUT/apk/aligned.apk"

echo "== DONE =="
ls -la "$(cygpath -u "$APKDIR")"/CF-IP-Keeper-debug.apk
