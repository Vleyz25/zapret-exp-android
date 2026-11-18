# Сторонние файлы

Код приложения (`app/src`, `app/tools`, скрипты сборки, тесты) — написан для этого
репозитория, лицензия MIT (см. `LICENSE`).

В `app/assets/` лежат файлы из дистрибутива zapret, они НЕ распространяются под MIT:

| Файл | Откуда |
|---|---|
| `pc/zapret-general.txt` | `lists/list-general.txt` + `lists/list-general-user.txt` |
| `pc/zapret-google.txt` | `lists/list-google.txt` |
| `pc/zapret-exclude.txt` | `lists/list-exclude.txt` + `lists/list-exclude-user.txt` |
| `pc/discordmedia.txt` | домен из `--hostlist-domains=discord.media` |
| `pc/*.bin` | `bin/tls_clienthello_www_sferum_ru.bin`, `bin/tls_clienthello_www_google_com.bin`, `bin/quic_initial_www_google_com.bin`, `bin/stun2.bin`, `bin/ACTIVE_DISCORD_UDP.bin` (сгенерированные fake-паттерны) |
| `pc/general-EXP.ref.bat` | корневой скрипт дистрибутива — только как эталон для сверки, приложением не исполняется |
| `rules-exp.txt` | этот репозиторий: правила, перенесённые из параметров того же bat |

Источник дистрибутива: [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
(сборка 1.10.4) с движком [bol-van/zapret](https://github.com/bol-van/zapret).

Ни `winws.exe`, ни `byedpi`, ни их код не компилируются, не линкуются и не входят в APK:
из дистрибутива использованы только данные (списки доменов и байтовые fake-паттерны) и
параметры стратегии. На момент публикации в репозитории bol-van/zapret файл лицензии
отсутствовал, а в Flowseal/zapret-discord-youtube она помечена как «NOASSERTION», поэтому
при перераспространении APK за пределы личной копии сверься с условиями upstream.
