package com.wiretap.extractor.io;

import com.wiretap.extractor.FrameSummary;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;

/**
 * SummaryWriter that writes JSONL to a provided Writer.
 * The underlying writer is not closed on close(); it is only flushed.
 */
public final class WriterSummaryWriter implements SummaryWriter {
    private final BufferedWriter writer;
    private final boolean pretty;

    public WriterSummaryWriter(Writer writer, boolean pretty) {
        this.writer = writer instanceof BufferedWriter ? (BufferedWriter) writer : new BufferedWriter(writer);
        this.pretty = pretty;
    }

    @Override
    public void write(FrameSummary summary) throws IOException {
        writer.write(summary.toJson(pretty));
        writer.write("\n");
        writer.flush();
    }

    @Override
    public void close() throws IOException {
        writer.flush();
        // intentionally do not close the underlying writer (e.g., HTTP response stream)
    }
}


