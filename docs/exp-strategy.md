# Перенос `general (EXP).bat` на Android: соответствие блоков и реализации

Источник: `C:\Users\Admin\OneDrive\Desktop\zapret-discord-youtube-1.10.4` (Flowseal
zapret-discord-youtube 1.10.4), файл `general (EXP).bat`, исполнитель `bin\winws.exe`
(WinDivert + desync на уровне пакетов).

Реализация на Android: приложение `ru.zapret.exp` — `VpnService`-туннель, пользовательская
TCP/UDP-точка, десинхронизация из `Desync.java`, правила из `assets/rules-exp.txt`,
списки и fake-паттерны из `assets/pc/` (копии файлов твоей папки).

## 1. Что делает bat (дословно)

```
--wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilterTCP%
--wf-udp=443,19294-19344,50000-50100,%GameFilterUDP%
```

| Блок | Условие | Приём | Перенесено в APK как |
|---|---|---|---|
| 1 | l7=quic, порты UDP 443 и 19294-19344/50000-50100, `list-general` + user, исключения `list-exclude`, `ipset-exclude` | `fake`, `repeats=11`, `fake-quic=quic_initial_www_google_com.bin` | правило `quic-general`: UDP 443,8443 + списки `zapret-general,zapret-google` → 11 фейковых QUIC-датаграмм с TTL 8 из того же `.bin` |
| 2 | UDP 19294-19344, 50000-50100, l7=discord/stun/unknown | `fake`, `repeats=4`, `cutoff=n4`, `ACTIVE_DISCORD_UDP.bin` | правило `discord-udp`: те же диапазоны портов, `repeat=4`, `ttl=8`, тот же `.bin` |
| 3 | TCP 2053,2083,2087,2096,8443, домен `discord.media` | `fake,multisplit`, `split-pos=1`, `seqovl=681`, `fooling=ts`, `repeats=8`, fake=google ClientHello | правило `discord-cdn`: фрагментация по 8 точкам от позиции 1 (`split=1:8:1`) + TLS record split; фейк — отдельным соединением с TTL 8 |
| 4 | TCP 443, `list-google` (YouTube/googlevideo/ytimg), `ip-id=zero` | `hostfakesplit`, `fooling=ts`, `mod=host=www.google.com` | правило `google-youtube`: фрагментация + фейк с подменой имени (`sni=www.google.com`, `Tls.withSni`) |
| 5 | TCP 80,443, `list-general` + user, исключения | `fake,multisplit`, `split-pos=1`, `seqovl=480`, `fooling=ts`, `repeats=4`, fake=`tls_clienthello_www_sferum_ru.bin` | правило `general-main`: фрагментация `split=1:4:1` + TLS record split; фейк тем же `.bin` отдельным соединением |
| 6 | UDP 443 по `ipset-all` | `fake`, `repeats=11` | **не переносится как есть**: `lists/ipset-all.txt` = `203.0.113.113/32` (заглушка) — на ПК блок не обрабатывает ничего. Вместо него `quic-general` по адресам из списков; для «по всем» есть закомментированное `quic-any` |
| 7 | TCP 80,443,8443 по `ipset-all` | `fake,multisplit`, `seqovl=480` | неактивно на ПК по той же причине (пустой ipset) |
| 8-9 | TCP/UDP `%GameFilterTCP%`, `%GameFilterUDP%` по `ipset-all` | `fake,multisplit`, `cutoff=n4` | не перенесено: игровые порты включаются только `service.bat load_game_filter`, плюс пустой ipset |

## 2. Чем обусловлены замены

Android без root не даёт: задавать номер последовательности, ставить TCP Timestamp,
вставлять байты в чужой поток, слать сырые пакеты. Всё это на ПК делает WinDivert.
Сокет-модель даёт ровно три рычага, и они используются:

| winws | рычаг в приложении | почему так |
|---|---|---|
| `--dpi-desync-split-pos=1` | несколько `Os.write()` с `TCP_NODELAY` | байтовый поток не меняется, меняется только нарезка сегментов — DPI видит «недостроенный» ClientHello |
| `--dpi-desync-multisplit --dpi-desync-repeats=N` | N точек разбиения (`Splits.cuts`) | шаг точки = `skip+1`, как в `byedpi`-записи `pos:repeats:skip` |
| `--dpi-desync=fake` (TCP) | фейк **отдельным TCP-соединением** с `IP_TTL=8` | врезка фейка в тот же поток сдвинула бы последовательность и убила TLS |
| `--dpi-desync=fake` (QUIC/UDP) | дополнительные датаграммы с `IP_TTL/IPV6_UNICAST_HOPS=8` | датаграммы независимы — приём перенесён точно |
| `--dpi-desync-fooling=ts` | малый TTL фейка | та же цель: пакет обработан инспекцией и не долетел до сервера |
| `--dpi-desync-fake-tls=<файл>` | `fake=<тот же файл>` | байты фейков — именно твои `.bin` из папки |
| `--dpi-desync-hostfakesplit-mod=host=...` | `sni=<домен>` → `Tls.withSni()` | подмена имени выполняется только при совпадении длины, чтобы не ломать структуры ClientHello |
| `--hostlist`, `--hostlist-exclude` | списки `zapret-*.txt` + `Config.HostSet` (синтаксис `^домен` = точное совпадение, без `^` = домен и поддомены) | |
| `--ipset` | карта IP→домен из собственных DNS-ответов (`Profile.learnDnsAnswer`) | аналог ipset для QUIC, где SNI зашифрован |
| `--new` (разделитель блоков) | порядок строк в `rules-exp.txt`, первое совпадение выигрывает | `Config.match()` |
| `--wf-*` (фильтр портов) | `ports=` в правиле + `Splits`/`matchTcp`/`matchUdp` | |

Что сознательно не переносится: `cutoff=n4`, `seqovl` в точном виде (перекрытие
последовательностей), `ip-id=zero`, игровые фильтры, `md5sig`/TCP-timestamp фоулинг.

## 3. Побочные эффекты, о которых надо знать

1. Групповые адреса и broadcast не релелятся → с включённым тумблером mDNS/Chromecast и
   «устройства в локальной сети» могут не находиться.
2. Обрыв соединения = RST клиенту, если поток уже умер (после 15-секундного «терпения»
   хвостовых ACK/FIN).
3. Каждое TCP-соединение живёт в пользовательском пространстве: очень медленные сети
   переносят это хуже, чем прямой путь без туннеля — при проблемах тумблер просто выключается.
4. Ограничение 400-512 одновременных потоков на протокол; при превышении новые отклоняются
   с записью в журнал.

## 4. Как подбирать, если в твоей сети чего-то не хватает

Порядок правок (это данные, а не код — пересборка занимает секунды):

1. `ttl` фейка: 8 → 5 → 2 (нужно, чтобы пакет умер до сервера, но дошёл до инспекции).
2. `split=1:4:1` → `1:8:1` (больше точек) или `1:2:1` (меньше).
3. Раскомментировать `quic-any` (фейки по всем UDP:443) либо `quic-block` (отбрасывать
   QUIC целиком, чтобы приложения ушли на TCP+TLS).
4. Дописывать домены в `zapret-general.txt`/`zapret-google.txt` — тот же формат, что в
   `lists/` на ПК, включая строки вида `^домен`.

После правки: `bash app/build.sh Zapret-EXP` (и `bash run_tests.sh`, чтобы проверить,
что конфиг не разъехался).
