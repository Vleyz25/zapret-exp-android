#!/usr/bin/env bash
# Сборка APK «Запрет (EXP)» без Gradle, без NDK, без сети.
#
# Исходники лежат в D:/Проекты/... (кириллица), но aapt2 в Windows не переваривает
# не-ASCII в путях аргументов, поэтому сборка идёт в ASCII- staging каталоге,
# а готовый APK копируется обратно к исходникам.
set -euo pipefail

SRC="D:/Проекты/zapret-exp-android/app"
STAGE="D:/zapret-build"
SDK="D:/Утилиты/AndroidBuildTools/sdk"
BT="$SDK/build-tools/34.0.0"
AJ="$SDK/platforms/android-34/android.jar"
JDK="D:/Утилиты/AndroidBuildTools/jdk/jdk-17.0.20.1+1"
KEY="D:/Проекты/zapret-exp-android/keys/zapret-exp.keystore"
KSPASS="zapret-exp"
MINAPI=24
TARGETAPI=34
VERCODE="${VERCODE:-1}"
VERNAME="${VERNAME:-1.0}"
NAME="${1:-Zapret-EXP}"

echo "### 0. staging в ASCII-путь"
mkdir -p "$STAGE"
for d in src res assets tools; do rm -rf "$STAGE/$d"; cp -r "$SRC/$d" "$STAGE/$d"; done
cp "$SRC/AndroidManifest.xml" "$STAGE/AndroidManifest.xml"
cp "$AJ" "$STAGE/android.jar"
cp "$KEY" "$STAGE/app.keystore"
rm -rf "$STAGE/gen" "$STAGE/build" "$STAGE/dist"
mkdir -p "$STAGE/gen" "$STAGE/build/classes" "$STAGE/build/dex" "$STAGE/build/tools" "$STAGE/dist"
cd "$STAGE"

echo "### 1. иконка"
"$JDK/bin/javac.exe" -encoding UTF-8 -d build/tools tools/MakeIcon.java
"$JDK/bin/java.exe" -cp build/tools MakeIcon res/drawable/ic_launcher.png 192

echo "### 2. aapt2 compile"
"$BT/aapt2.exe" compile --dir res -o gen/res.zip

echo "### 3. aapt2 link"
"$BT/aapt2.exe" link --auto-add-overlay \
  -I android.jar \
  --manifest AndroidManifest.xml \
  --java gen/java \
  -A assets \
  --min-sdk-version $MINAPI \
  --target-sdk-version $TARGETAPI \
  --version-code "$VERCODE" \
  --version-name "$VERNAME" \
  -o gen/base.apk \
  gen/res.zip

echo "### 4. javac"
SOURCES=$(find src gen/java -name "*.java" | tr '\n' ' ')
"$JDK/bin/javac.exe" -nowarn -Xlint:-options -encoding UTF-8 \
  -source 8 -target 8 \
  -bootclasspath android.jar \
  -d build/classes $SOURCES

echo "### 5. d8"
CLASSES=$(find build/classes -name "*.class" | tr '\n' ' ')
"$JDK/bin/java.exe" -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
  --release --min-api $MINAPI --lib android.jar --classpath android.jar \
  --output build/dex $CLASSES

echo "### 6. dex -> APK"
python - <<'PY'
import zipfile
zin = zipfile.ZipFile("gen/base.apk")
zout = zipfile.ZipFile("build/app.unsigned.apk", "w", zipfile.ZIP_DEFLATED)
for it in zin.infolist():
    if it.filename.startswith("META-INF/"):
        continue
    zout.writestr(it, zin.read(it.filename))
zout.write("build/dex/classes.dex", "classes.dex")
zout.close(); zin.close()
print("dex вшит")
PY

echo "### 7. zipalign + подпись"
"$BT/zipalign.exe" -f 4 build/app.unsigned.apk build/app.aligned.apk
APKSIGNER="$JDK/bin/java.exe -cp $BT/lib/apksigner.jar com.android.apksigner.ApkSignerTool"
$APKSIGNER sign \
  --ks app.keystore --ks-key-alias zapret-exp --ks-pass "pass:$KSPASS" --key-pass "pass:$KSPASS" \
  --min-sdk-version $MINAPI --out "dist/$NAME.apk" build/app.aligned.apk

echo "### 8. проверка"
$APKSIGNER verify --print-certs "dist/$NAME.apk" | head -5
echo "--- badging ---"
"$BT/aapt2.exe" dump badging "dist/$NAME.apk" | grep -E "^(package|application-label|launchable-activity|sdkVersion|targetSdkVersion|uses-permission|density|icon)" | sed 's/^/  /'
echo "--- содержимое ---"
python - "$NAME" <<'PY'
import sys, zipfile
z = zipfile.ZipFile("dist/%s.apk" % sys.argv[1])
n = [i.filename for i in z.infolist()]
print("  файлов:", len(n))
print("  assets:", sorted(x for x in n if x.startswith("assets/")))
print("  dex:", [x for x in n if x.endswith(".dex")])
PY

rm -f app.keystore   # копия ключа в staging не должна оставаться

echo "### 9. копирование APK к исходникам"
mkdir -p "$SRC/dist"
cp "dist/$NAME.apk" "$SRC/dist/$NAME.apk"
ls -la "$SRC/dist/"
