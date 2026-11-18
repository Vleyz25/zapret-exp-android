package ru.zapret.exp;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/** Счётчики и короткий журнал того, что реально делал движок. */
public final class Stats {

    public final AtomicLong tcpFlows = new AtomicLong();
    public final AtomicLong udpFlows = new AtomicLong();
    public final AtomicLong desyncTls = new AtomicLong();
    public final AtomicLong desyncHttp = new AtomicLong();
    public final AtomicLong desyncQuic = new AtomicLong();
    public final AtomicLong bytesDown = new AtomicLong();
    public final AtomicLong bytesUp = new AtomicLong();
    public final AtomicLong dnsLearned = new AtomicLong();
    public final AtomicLong dropped = new AtomicLong();

    private final ArrayDeque<String> log = new ArrayDeque<>();
    private static final int LOG_MAX = 120;

    public void log(String line) {
        synchronized (log) {
            log.addFirst(line);
            while (log.size() > LOG_MAX) log.removeLast();
        }
    }

    public List<String> logCopy() {
        synchronized (log) {
            return new ArrayList<>(log);
        }
    }

    public void reset() {
        tcpFlows.set(0); udpFlows.set(0);
        desyncTls.set(0); desyncHttp.set(0); desyncQuic.set(0);
        bytesDown.set(0); bytesUp.set(0); dnsLearned.set(0); dropped.set(0);
        synchronized (log) { log.clear(); }
    }
}
