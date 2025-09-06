package com.wiretap.web;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;

/**
 * Simple in-process pub/sub bus for streaming JSONL lines to SSE clients.
 */
public final class LiveBus {
    private static final Set<Subscriber> subs = new CopyOnWriteArraySet<>();

    public static Subscriber subscribe(Consumer<String> consumer) {
        Subscriber s = new Subscriber(consumer);
        subs.add(s);
        return s;
    }

    public static void unsubscribe(Subscriber s) {
        if (s != null) subs.remove(s);
    }

    public static void publish(String line) {
        // Store frame in session if HttpApp instance exists
        if (HttpApp.getCurrentInstance() != null) {
            HttpApp.getCurrentInstance().addSessionFrame(line);
        }

        for (Subscriber s : subs) {
            try { s.consumer.accept(line); } catch (Throwable ignored) {}
        }
    }

    public static final class Subscriber {
        private final Consumer<String> consumer;
        private Subscriber(Consumer<String> c) { this.consumer = c; }
    }
}


