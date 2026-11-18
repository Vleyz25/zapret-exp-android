#!/usr/bin/env bash
# Сборка APK «Запрет (EXP)» без Gradle, без NDK, без сети.
#
#   aapt2 compile -> aapt2 link -> javac -> d8 -> вшивка classes.dex -> zipalign -> apksigner
#
# Нужны только JDK 17 и Android SDK (platform + build-tools), дальше всё штатные утилиты.
# Пути задаются переменными окружения (JAVA_HOME / ANDROID_HOME) или файлом local.env
# в корне репозитория — он не попадает в git (см. .gitignore), там же ключ и его пароль.
#
#   JAVA_HOME=/c/tools/jdk-17 ANDROID_HOME=/c/tools/android/sdk \
#   KEY=keys/my.keystore KSAlias=my KSPass='секрет' bash app/build.sh Zapret-EXP
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # .../<repo>/app
ROOT="$(cd "$HERE/.." && pwd)"                            # корень репозитория
if [ -f "$ROOT/local.env" ]; then . "$ROOT/local.env"; fi

SDK="${SDK:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}}"
JDK="${JDK:-${JAVA_HOME:-}}"
BUILD_TOOLS="${BUILD_TOOLS:-34.0.0}"
PLATFORM="${PLATFORM:-android-34}"
KEY="${KEY:-$ROOT/keys/zapret-exp.keystore}"
KSAlias="${KSAlias:-zapret-exp}"
KSPass="${KSPass:-}"

MINAPI=24
TARGETAPI=34
VERCODE="${VERCODE:-1}"
VERNAME="${VERNAME:-1.0}"
NAME="${1:-Zapret-EXP}"

# aapt2 в Windows не читает не-ASCII пути в аргументах, поэтому сборка идёт в
# staging-каталоге с ASCII-путём. Готовый APK скрипт копирует обратно к исходникам.
STAGE="${STAGE:-/tmp/zapret-build}"
BT="$SDK/build-tools/$BUILD_TOOLS"
AJ="$SDK/platforms/$PLATFORM/android.jar"

if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then echo "Не задан SDK (ANDROID_HOME или SDK= в local.env)"; exit 1; fi
if [ -z "$JDK" ] || [ ! -d "$JDK" ]; then echo "Не задан JDK (JAVA_HOME или JDK= в local.env)"; exit 1; fi
if [ ! -f "$AJ" ]; then echo "Нет платформы: $AJ"; exit 1; fi
if [ ! -f "$KEY" ]; then echo "Нет ключа подписи: $KEY (создай: keytool -genkeypair -keystore keys/my.keystore -alias my -keyalg RSA -keysize 2048 -validity 10000)"; exit 1; fi
if [ -z "$KSPass" ]; then echo "Задай пароль ключа: KSPass='...' (или в local.env)"; exit 1; fi
case "$STAGE" in
    *[!a-zA-Z0-9/._:-]*) echo "STAGE должен быть ASCII-путём, сейчас: $STAGE"; exit 1 ;;
esac

echo "### 0. staging: $STAGE"
mkdir -p "$STAGE"
for d in src res assets tools; do rm -rf "$STAGE/$d"; cp -r "$HERE/$d" "$STAGE/$d"; done
cp "$HERE/AndroidManifest.xml" "$STAGE/AndroidManifest.xml"
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

echo "### 3. aapt2 link (min $MINAPI / target $TARGETAPI / $VERNAME)"
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
print("  dex вшит")
PY

echo "### 7. zipalign + подпись"
"$BT/zipalign.exe" -f 4 build/app.unsigned.apk build/app.aligned.apk
APKSIGNER="$JDK/bin/java.exe -cp $BT/lib/apksigner.jar com.android.apksigner.ApkSignerTool"
$APKSIGNER sign \
  --ks app.keystore --ks-key-alias "$KSAlias" --ks-pass "pass:$KSPass" --key-pass "pass:$KSPass" \
  --min-sdk-version $MINAPI --out "dist/$NAME.apk" build/app.aligned.apk
rm -f app.keystore

echo "### 8. проверка"
$APKSIGNER verify "dist/$NAME.apk" && echo "  подпись OK"
echo "--- badging ---"
"$BT/aapt2.exe" dump badging "dist/$NAME.apk" | grep -E "^(package|application-label|launchable-activity|sdkVersion|targetSdkVersion|uses-permission)" | sed 's/^/  /'
echo "--- содержимое ---"
python - "$NAME" <<'PY'
import sys, zipfile
z = zipfile.ZipFile("dist/%s.apk" % sys.argv[1])
n = [i.filename for i in z.infolist()]
print("  файлов:", len(n))
print("  assets:", len([x for x in n if x.startswith("assets/")]), sorted(x.split("/")[-1] for x in n if x.startswith("assets/")))
print("  dex:", [x for x in n if x.endswith(".dex")])
PY

echo "### 9. APK к исходникам"
mkdir -p "$HERE/dist"
cp "dist/$NAME.apk" "$HERE/dist/$NAME.apk"
echo "готово: $HERE/dist/$NAME.apk"
