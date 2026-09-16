package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.42.0: 存储静态加密契约测试。
 * 1) 写入后文件带 magic 帧头；2) 透明读回内容一致；3) 篡改密文读取必失败；
 * 4) 关闭加密时明文直通（上传链路永不中断）。
 */
class StorageCryptoServiceTest {

    private StorageCryptoService service;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() throws Exception {
        service = new StorageCryptoService();
        setField("enabled", true);
        setField("keyFile", tempDir.resolve("keys/storage-master.key").toString());
    }

    private void setField(String name, Object value) throws Exception {
        var field = StorageCryptoService.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(service, value);
    }

    @Test
    void roundtrip_encryptsAndDecrypts() throws Exception {
        byte[] plain = "hello ironwall storage".getBytes();
        Path file = tempDir.resolve("a.bin");
        try (OutputStream out = service.openWrite(file, plain.length)) {
            out.write(plain);
        }
        assertTrue(service.isEncrypted(file), "加密文件应带 IWENC001 帧头");
        assertEquals(plain.length, service.plainLength(file), "明文长度应还原");
        try (InputStream in = service.openRead(file)) {
            assertArrayEquals(plain, in.readAllBytes(), "透明读内容应一致");
        }
    }

    @Test
    void tamperedCiphertext_failsOnRead() throws Exception {
        byte[] plain = new byte[StorageCryptoService.CHUNK_SIZE + 100];
        for (int i = 0; i < plain.length; i++) {
            plain[i] = (byte) (i % 251);
        }
        Path file = tempDir.resolve("b.bin");
        try (OutputStream out = service.openWrite(file, plain.length)) {
            out.write(plain);
        }
        byte[] bytes = Files.readAllBytes(file);
        // 篡改第二个分块（文件尾部）的密文字节
        bytes[bytes.length - 8] ^= 0x01;
        Files.write(file, bytes);
        try (InputStream in = service.openRead(file)) {
            assertThrows(java.io.IOException.class, in::readAllBytes, "GCM 标签校验失败必须抛异常");
        }
    }

    @Test
    void disabledEncryption_writesPlaintext() throws Exception {
        setField("enabled", false);
        byte[] plain = "plain passthrough".getBytes();
        Path file = tempDir.resolve("c.bin");
        try (OutputStream out = service.openWrite(file, plain.length)) {
            out.write(plain);
        }
        assertFalse(service.isEncrypted(file), "关闭加密时应写明文");
        assertArrayEquals(plain, Files.readAllBytes(file));
        try (InputStream in = service.openRead(file)) {
            assertArrayEquals(plain, in.readAllBytes());
        }
    }

    @Test
    void unknownSize_doesNotBreakUpload() throws Exception {
        Path file = tempDir.resolve("d.bin");
        try (OutputStream out = service.openWrite(file, 0)) {
            out.write("still writable".getBytes());
        }
        assertTrue(Files.size(file) > 0, "未知尺寸也应落盘成功");
    }
}
