package com.jdy.cloud.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * IronWall v1.43.0: multipart 上传完整性哈希（前后端一致）。
 *
 * 算法：sha256(首 64KiB 字节 + "|" + 文件大小(十进制) + "|" + 尾 64KiB 字节)。
 * 首/尾切片与前端 File.slice 语义完全一致：
 * first = bytes[0, min(size, 64KiB))
 * last = bytes[max(0, size-64KiB), size)
 * 小文件(<=128KiB)整体缓冲后按切片计算；大文件单遍流式读取，零全量读开销。
 */
public final class FileIntegrityHash {

    public static final int CHUNK_BYTES = 64 * 1024;

    /** 小于等于该值时整体缓冲（首尾切片重叠，单遍流无法表达）。 */
    private static final int BUFFER_THRESHOLD = 2 * CHUNK_BYTES;

    private FileIntegrityHash() {
    }

    /** 内存字节的部分哈希（头像等小文件）。 */
    public static String ofBytes(byte[] data) {
        if (data == null) {
            return null;
        }
        return hashSegments(data, data.length);
    }

    /** 流式部分哈希：小文件整体缓冲，大文件读首/尾各 64KiB。 */
    public static String ofStream(InputStream in, long size) {
        if (in == null || size < 0) {
            return null;
        }
        try {
            if (size <= BUFFER_THRESHOLD) {
                return hashSegments(readN(in, (int) size), size);
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(readN(in, CHUNK_BYTES));
            md.update((byte) '|');
            md.update(String.valueOf(size).getBytes(StandardCharsets.UTF_8));
            md.update((byte) '|');
            skipFully(in, size - 2L * CHUNK_BYTES);
            md.update(readN(in, CHUNK_BYTES));
            return toHex(md.digest());
        } catch (Exception e) {
            return null;
        }
    }

    /** 与前端 File.slice 语义一致的首/尾切片哈希。 */
    private static String hashSegments(byte[] data, long size) {
        try {
            int firstLen = (int) Math.min(CHUNK_BYTES, size);
            int lastStart = (int) Math.max(0, size - CHUNK_BYTES);
            int lastLen = (int) (size - lastStart);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data, 0, firstLen);
            md.update((byte) '|');
            md.update(String.valueOf(size).getBytes(StandardCharsets.UTF_8));
            md.update((byte) '|');
            md.update(data, lastStart, lastLen);
            return toHex(md.digest());
        } catch (Exception e) {
            return null;
        }
    }

    private static void skipFully(InputStream in, long toSkip) throws IOException {
        long skipped = 0;
        byte[] buf = new byte[8192];
        while (skipped < toSkip) {
            int n = in.read(buf, 0, (int) Math.min(buf.length, toSkip - skipped));
            if (n < 0) {
                break;
            }
            skipped += n;
        }
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(0, n));
        byte[] buf = new byte[8192];
        int remain = n;
        while (remain > 0) {
            int r = in.read(buf, 0, Math.min(buf.length, remain));
            if (r < 0) {
                break;
            }
            bos.write(buf, 0, r);
            remain -= r;
        }
        return bos.toByteArray();
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
