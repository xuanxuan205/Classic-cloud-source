package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * IronWall v1.43.0: multipart 部分哈希（首64KiB|size|尾64KiB）契约测试。
 */
class FileIntegrityHashTest {

    @Test
    void smallFile_bytesAndStreamAgree() {
        byte[] data = "hello integrity".getBytes(StandardCharsets.UTF_8);
        String h1 = FileIntegrityHash.ofBytes(data);
        String h2 = FileIntegrityHash.ofStream(new ByteArrayInputStream(data), data.length);
        assertEquals(h1, h2);
        assertEquals(64, h1.length());
    }

    @Test
    void largeFile_slicesAreStableAndTamperSensitive() {
        byte[] data = new byte[200 * 1024];
        new Random(42).nextBytes(data);
        String h1 = FileIntegrityHash.ofBytes(data);
        String h2 = FileIntegrityHash.ofStream(new ByteArrayInputStream(data), data.length);
        assertEquals(h1, h2);
        data[data.length - 1] ^= 0x01;
        assertNotEquals(h1, FileIntegrityHash.ofBytes(data));
        data[0] ^= 0x01;
        assertNotEquals(h1, FileIntegrityHash.ofBytes(data));
    }
}
