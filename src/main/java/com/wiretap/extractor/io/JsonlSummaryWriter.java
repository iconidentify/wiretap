package com.wiretap.extractor.io;

import com.wiretap.extractor.FrameSummary;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.zip.GZIPOutputStream;

public final class JsonlSummaryWriter implements SummaryWriter {
    private final BufferedWriter writer;
    private final boolean pretty;

    public JsonlSummaryWriter(Path file, boolean gzip, boolean pretty) throws IOException {
        this.pretty = pretty;
        var fos = new FileOutputStream(file.toFile());
        if (gzip) {
            this.writer = new BufferedWriter(new OutputStreamWriter(new GZIPOutputStream(fos), StandardCharsets.UTF_8));
        } else {
            this.writer = new BufferedWriter(new OutputStreamWriter(fos, StandardCharsets.UTF_8));
        }
    }

    @Override
    public void write(FrameSummary summary) throws IOException {
        writer.write(summary.toJson(pretty));
        writer.write("\n");
    }

    @Override
    public void close() throws IOException {
        writer.flush();
        writer.close();
    }
}


