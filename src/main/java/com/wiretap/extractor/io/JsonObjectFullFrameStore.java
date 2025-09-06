package com.wiretap.extractor.io;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

public final class JsonObjectFullFrameStore implements FullFrameStore {
    private final Path file;
    private final boolean gzip;
    private final Map<String, String> dict = new LinkedHashMap<>();

    public JsonObjectFullFrameStore(Path file, boolean gzip) {
        this.file = file;
        this.gzip = gzip;
    }

    @Override
    public void put(String key, String fullHex) {
        dict.putIfAbsent(key, fullHex);
    }

    @Override
    public boolean contains(String key) {
        return dict.containsKey(key);
    }

    @Override
    public void close() throws IOException {
        try (var fos = new FileOutputStream(file.toFile());
             var osw = gzip
                     ? new OutputStreamWriter(new GZIPOutputStream(fos), StandardCharsets.UTF_8)
                     : new OutputStreamWriter(fos, StandardCharsets.UTF_8);
             var w = new BufferedWriter(osw)) {
            w.write("{\"frames\":{");
            boolean first = true;
            for (var e : dict.entrySet()) {
                if (!first) w.write(",");
                first = false;
                w.write("\""); w.write(e.getKey()); w.write("\":\"");
                w.write(e.getValue()); w.write("\"");
            }
            w.write("}}");
        }
    }
}


