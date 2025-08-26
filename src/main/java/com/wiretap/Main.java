package com.wiretap;

import com.wiretap.extractor.AolExtractor;
import com.wiretap.extractor.io.FullFrameStore;
import com.wiretap.extractor.io.JsonObjectFullFrameStore;
import com.wiretap.extractor.io.JsonlSummaryWriter;
import com.wiretap.extractor.io.SummaryWriter;
import com.wiretap.web.HttpApp;

import java.nio.file.Path;

public final class Main {
    public static void main(String[] args) throws Exception {
        String pcap = null;
        String outBase = "session";
        int serverPort = 5190;
        boolean pretty = false;
        boolean storeFull = false;
        boolean serve = false;
        int httpPort = 8080;

        for (int i = 0; i < args.length; i++) {
            String k = args[i];
            String v = (i + 1 < args.length && !args[i + 1].startsWith("--")) ? args[++i] : null;
            switch (k) {
                case "--pcap" -> pcap = v;
                case "--out" -> outBase = v == null ? outBase : v;
                case "--server-port" -> serverPort = v == null ? serverPort : Integer.parseInt(v);
                case "--pretty" -> pretty = true;
                case "--store-full" -> storeFull = true;
                case "--serve" -> serve = true;
                case "--port" -> httpPort = v == null ? httpPort : Integer.parseInt(v);
                case "--help", "-h" -> {
                    System.out.println("Usage: java -jar pcap-extractor-standalone.jar --pcap <file> [--out base] [--server-port 5190] [--pretty] [--store-full]\n"
                            + "       java -jar pcap-extractor-standalone.jar --serve [--port 8080] [--server-port 5190]");
                    return;
                }
            }
        }

        if (serve) {
            new HttpApp(httpPort, serverPort).start();
            return;
        }

        if (pcap == null) {
            throw new IllegalArgumentException("--pcap is required");
        }

        Path summaryPath = Path.of(outBase + ".summary.jsonl.gz");
        Path framesPath = Path.of(outBase + ".frames.json.gz");

        SummaryWriter summary = new JsonlSummaryWriter(summaryPath, true, pretty);
        FullFrameStore frames = storeFull ? new JsonObjectFullFrameStore(framesPath, true) : null;
        try (summary; frames) {
            new AolExtractor().extract(pcap, serverPort, pretty, storeFull, summary, frames);
        }
    }
}


