package com.wiretap.extractor.io;

import com.wiretap.extractor.FrameSummary;

import java.io.Closeable;
import java.io.IOException;

public interface SummaryWriter extends Closeable {
    void write(FrameSummary summary) throws IOException;
    @Override
    void close() throws IOException;
}


