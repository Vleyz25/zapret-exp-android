#!/usr/bin/env bash
# Стенд TCP-ретранслятора на обычной JVM: синтетический TCP-клиент <-> наш TcpFlow <-> реальный сервер.
# Не требует ни телефона, ни Android: компилируется против android.jar, но исполняется на обычной JVM.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f local.env ]; then . ./local.env; fi
J="${JDK:-${JAVA_HOME:-}}"
SDK="${SDK:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}}"
if [ -z "$J" ] || [ -z "$SDK" ]; then echo "Нужны JDK и SDK (см. local.env)"; exit 1; fi
AJ="$SDK/platforms/${PLATFORM:-android-34}/android.jar"
rm -rf build/relay; mkdir -p build/relay
SRC="app/src/ru/zapret/exp"
"$J/bin/javac.exe" -nowarn -encoding UTF-8 -cp "$AJ" -d build/relay \
  tests/RelayTest.java \
  "$SRC/Bits.java" "$SRC/Hello.java" "$SRC/Splits.java" "$SRC/Config.java" \
  "$SRC/Stats.java" "$SRC/Tls.java" "$SRC/Window.java" "$SRC/Net.java" \
  "$SRC/Desync.java" "$SRC/Profile.java" "$SRC/TcpFlow.java"
"$J/bin/java.exe" -cp build/relay ru.zapret.exp.RelayTest
