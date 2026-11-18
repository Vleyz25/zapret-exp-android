#!/usr/bin/env bash
# Проверки ядра на обычной JVM: без Android, без телефона, без сети.
# Разбор/сборка пакетов, SNI из fake-паттернов, DNS, инварианты фрагментации,
# управление окном, весь конфиг и правила из APK.
#
#   JAVA_HOME=/c/tools/jdk-17 bash run_tests.sh
#
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f local.env ]; then . ./local.env; fi
J="${JDK:-${JAVA_HOME:-}}"
if [ -z "$J" ] || [ ! -d "$J" ]; then echo "Нужен JDK 17: JAVA_HOME=... или JDK= в local.env"; exit 1; fi

rm -rf build/test
mkdir -p build/test
"$J/bin/javac.exe" -encoding UTF-8 -d build/test \
  tests/CoreTest.java \
  app/src/ru/zapret/exp/Bits.java \
  app/src/ru/zapret/exp/Window.java \
  app/src/ru/zapret/exp/Hello.java \
  app/src/ru/zapret/exp/Splits.java \
  app/src/ru/zapret/exp/Config.java \
  app/src/ru/zapret/exp/Stats.java \
  app/src/ru/zapret/exp/Tls.java
"$J/bin/java.exe" -cp build/test ru.zapret.exp.CoreTest "app/assets/pc"
