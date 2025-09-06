package com.wiretap.extractor.io;

import java.io.Closeable;
import java.io.IOException;

public interface FullFrameStore extends Closeable {
    void put(String key, String fullHex) throws IOException;
    boolean contains(String key) throws IOException;
    @Override
    void close() throws IOException;
}


