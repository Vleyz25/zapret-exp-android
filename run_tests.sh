#!/usr/bin/env bash
# Проверки ядра (разбор/сборка пакетов, SNI из fake-паттернов, DNS, фрагментация)
# на обычной JVM: без Android, без телефона, без сети.
set -euo pipefail
cd "D:/Проекты/zapret-exp-android"
J="D:/Утилиты/AndroidBuildTools/jdk/jdk-17.0.20.1+1"
rm -rf build/test
mkdir -p build/test
"$J/bin/javac.exe" -encoding UTF-8 -d build/test \
  tests/CoreTest.java \
  app/src/ru/zapret/exp/Bits.java \
  app/src/ru/zapret/exp/Config.java \
  app/src/ru/zapret/exp/Hello.java \
  app/src/ru/zapret/exp/Splits.java \
  app/src/ru/zapret/exp/Tls.java
"$J/bin/java.exe" -Dfile.encoding=UTF-8 -cp build/test ru.zapret.exp.CoreTest app/assets/pc
