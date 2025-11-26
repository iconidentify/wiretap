package com.wiretap.session;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SessionWriter.
 */
class SessionWriterTest {

    @TempDir
    Path tempDir;

    private SessionWriter writer;
    private Path sessionFile;
    private SessionInfo sessionInfo;

    @BeforeEach
    void setUp() throws IOException {
        sessionFile = tempDir.resolve("test-session.jsonl");
        sessionInfo = new SessionInfo("test-session");
        writer = new SessionWriter(sessionFile, sessionInfo);
    }

    @AfterEach
    void tearDown() {
        if (writer != null) {
            writer.close();
        }
    }

    @Test
    @DisplayName("append adds frames to buffer")
    void testAppend() {
        writer.append("{\"frame\":1}");
        writer.append("{\"frame\":2}");

        assertEquals(2, writer.getFrameCount());
        assertEquals(2, sessionInfo.getFrameCount());
    }

    @Test
    @DisplayName("flush writes buffered data to disk")
    void testFlush() throws IOException {
        writer.append("{\"frame\":1}");
        writer.append("{\"frame\":2}");
        writer.flush();

        assertTrue(Files.exists(sessionFile));
        List<String> lines = Files.readAllLines(sessionFile);
        assertEquals(2, lines.size());
        assertEquals("{\"frame\":1}", lines.get(0));
        assertEquals("{\"frame\":2}", lines.get(1));
    }

    @Test
    @DisplayName("close flushes remaining data and marks session ended")
    void testClose() throws IOException {
        writer.append("{\"frame\":1}");
        writer.close();
        writer = null; // Prevent double close in tearDown

        assertTrue(Files.exists(sessionFile));
        List<String> lines = Files.readAllLines(sessionFile);
        assertEquals(1, lines.size());
        assertFalse(sessionInfo.isActive());
        assertNotNull(sessionInfo.getEndTime());
    }

    @Test
    @DisplayName("getSessionFile returns correct path")
    void testGetSessionFile() {
        assertEquals(sessionFile, writer.getSessionFile());
    }

    @Test
    @DisplayName("getSessionInfo returns correct info object")
    void testGetSessionInfo() {
        assertSame(sessionInfo, writer.getSessionInfo());
    }

    @Test
    @DisplayName("Multiple appends create valid JSONL file")
    void testMultipleAppends() throws IOException {
        for (int i = 0; i < 100; i++) {
            writer.append("{\"frame\":" + i + ",\"data\":\"test\"}");
        }
        writer.flush();

        List<String> lines = Files.readAllLines(sessionFile);
        assertEquals(100, lines.size());

        // Verify each line is valid JSON
        for (int i = 0; i < lines.size(); i++) {
            assertTrue(lines.get(i).startsWith("{"));
            assertTrue(lines.get(i).endsWith("}"));
            assertTrue(lines.get(i).contains("\"frame\":" + i));
        }
    }

    @Test
    @DisplayName("Writer updates file size in session info")
    void testFileSizeUpdate() throws IOException {
        writer.append("{\"test\":\"data with some content to have measurable size\"}");
        writer.flush();

        // File size should be updated
        long actualSize = Files.size(sessionFile);
        assertTrue(actualSize > 0);
        assertEquals(actualSize, sessionInfo.getFileSizeBytes());
    }

    @Test
    @DisplayName("Writer handles concurrent appends")
    void testConcurrentAppends() throws Exception {
        int threadCount = 4;
        int framesPerThread = 100;
        Thread[] threads = new Thread[threadCount];

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            threads[t] = new Thread(() -> {
                for (int i = 0; i < framesPerThread; i++) {
                    writer.append("{\"thread\":" + threadId + ",\"frame\":" + i + "}");
                }
            });
        }

        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            thread.join();
        }

        writer.flush();

        assertEquals(threadCount * framesPerThread, writer.getFrameCount());

        List<String> lines = Files.readAllLines(sessionFile);
        assertEquals(threadCount * framesPerThread, lines.size());
    }
}
