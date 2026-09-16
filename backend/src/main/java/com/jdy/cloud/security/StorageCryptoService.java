package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.AbstractResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * IronWall v1.42.0: 上传文件静态加密（透明读写，存量零迁移）。
 *
 * 文件格式（帧化 AES-256-GCM，支持流式写入/读取与分片合并）：
 * [8B magic "IWENC001"]
 * [8B 原始明文长度 BE]
 * [60B 文件密钥封装：12B nonce + 48B AES-GCM(masterKey, fileKey)]
 * [4B 分块大小 BE（默认 1 MiB）]
 * 之后每个分块：[4B 明文长度][12B nonce][密文+16B GCM tag]
 *
 * 主密钥来源优先级：环境变量 IRONWALL_STORAGE_KEY（base64 32 字节）>
 * key-file（首次自动生成并持久化，权限 600 尽力收敛）。
 * 主密钥不可用时写路径自动降级为明文并告警（上传永不中断）；读路径按 magic 自动识别，
 * 旧明文文件与加密文件并存无感。运维红线：key 文件必须纳入备份，绝不删除，否则历史
 * 加密文件不可读。
 */
@Slf4j
@Component
public class StorageCryptoService {

    public static final String MAGIC = "IWENC001";
    public static final int CHUNK_SIZE = 1024 * 1024;
    private static final int HEADER_SIZE = 8 + 8 + 12 + 48 + 4;
    private static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Value("${app.storage.encryption.enabled:true}")
    private boolean enabled;

    @Value("${app.storage.encryption.key-file:${STORAGE_ENCRYPTION_KEY_FILE:./config/storage-master.key}}")
    private String keyFile;

    private volatile byte[] masterKey;
    private volatile boolean keyUnavailable;

    /** 主密钥懒加载；失败只降级并告警，绝不抛异常阻断上传链路。 */
    private byte[] masterKeyOrNull() {
        if (masterKey != null) {
            return masterKey;
        }
        synchronized (this) {
            if (masterKey != null) {
                return masterKey;
            }
            if (keyUnavailable) {
                return null;
            }
            try {
                String env = System.getenv("IRONWALL_STORAGE_KEY");
                if (env != null && !env.isBlank()) {
                    byte[] key = Base64.getDecoder().decode(env.trim());
                    if (key.length != 32) {
                        log.error("[IronWall] IRONWALL_STORAGE_KEY must be base64(32 bytes), storage encryption disabled");
                        keyUnavailable = true;
                        return null;
                    }
                    masterKey = key;
                    log.info("[IronWall] storage master key loaded from IRONWALL_STORAGE_KEY");
                    return masterKey;
                }
                Path keyPath = Path.of(keyFile).toAbsolutePath().normalize();
                if (Files.exists(keyPath)) {
                    String raw = new String(Files.readAllBytes(keyPath), StandardCharsets.UTF_8).trim();
                    byte[] key = Base64.getDecoder().decode(raw);
                    if (key.length != 32) {
                        log.error("[IronWall] storage master key file invalid ({}), storage encryption disabled", keyPath);
                        keyUnavailable = true;
                        return null;
                    }
                    masterKey = key;
                    return masterKey;
                }
                byte[] key = new byte[32];
                RANDOM.nextBytes(key);
                Files.createDirectories(keyPath.getParent());
                Files.write(keyPath, (Base64.getEncoder().encodeToString(key) + System.lineSeparator())
                        .getBytes(StandardCharsets.UTF_8));
                try {
                    keyPath.toFile().setReadable(true, true);
                    keyPath.toFile().setWritable(true, true);
                } catch (Exception ignored) {
                    // 权限收敛尽力而为
                }
                masterKey = key;
                log.warn("[IronWall] storage master key generated at {} (must be backed up)", keyPath);
                return masterKey;
            } catch (Exception e) {
                log.error("[IronWall] storage master key unavailable, falling back to plaintext writes: {}",
                        e.getMessage());
                keyUnavailable = true;
                return null;
            }
        }
    }

    public boolean isEncryptionReady() {
        return enabled && masterKeyOrNull() != null;
    }

    /** 文件是否为加密帧格式（读前 8 字节 magic）。 */
    public boolean isEncrypted(Path file) {
        try {
            if (file == null || !Files.exists(file)) {
                return false;
            }
            try (InputStream in = Files.newInputStream(file)) {
                byte[] head = new byte[MAGIC.length()];
                int n = 0;
                while (n < head.length) {
                    int r = in.read(head, n, head.length - n);
                    if (r < 0) {
                        break;
                    }
                    n += r;
                }
                return n == head.length && MAGIC.equals(new String(head, StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            return false;
        }
    }

    /** 明文长度：加密文件读头部原始长度；普通文件用磁盘大小。 */
    public long plainLength(Path file) {
        try {
            if (isEncrypted(file)) {
                try (InputStream in = Files.newInputStream(file)) {
                    byte[] header = in.readNBytes(HEADER_SIZE);
                    if (header.length < HEADER_SIZE) {
                        return -1;
                    }
                    ByteBuffer buf = ByteBuffer.wrap(header);
                    buf.position(MAGIC.length());
                    return buf.getLong();
                }
            }
            return Files.size(file);
        } catch (Exception e) {
            try {
                return Files.size(file);
            } catch (IOException io) {
                return -1;
            }
        }
    }

    /** 透明读流：加密文件自动解密，普通文件原样。 */
    public InputStream openRead(Path file) throws IOException {
        if (file == null || !Files.exists(file)) {
            throw new IOException("file not found");
        }
        if (isEncrypted(file)) {
            byte[] key = masterKeyOrNull();
            if (key == null) {
                throw new IOException("storage master key unavailable");
            }
            return new DecryptingInputStream(Files.newInputStream(file), key);
        }
        return Files.newInputStream(file);
    }

    /** 透明写流：加密就绪时写加密帧；否则明文（上传链路永不中断）。 */
    public OutputStream openWrite(Path file, long expectedPlainSize) throws IOException {
        if (isEncryptionReady() && expectedPlainSize > 0) {
            return new EncryptingOutputStream(Files.newOutputStream(file), masterKeyOrNull(), expectedPlainSize);
        }
        if (enabled && expectedPlainSize <= 0) {
            log.warn("[IronWall] plaintext write fallback for {}: unknown size", file);
        }
        return Files.newOutputStream(file);
    }

    /** 下载资源：加密文件给出流式解密资源（Range 重开流），普通文件保持 FileSystemResource。 */
    public Resource resourceOf(Path file) {
        if (file == null) {
            return new FileSystemResource((Path) null);
        }
        if (!isEncrypted(file)) {
            return new FileSystemResource(file);
        }
        return new EncryptedFileResource(file);
    }

    private final class EncryptedFileResource extends AbstractResource {
        private final Path path;

        EncryptedFileResource(Path path) {
            this.path = path;
        }

        @Override
        public String getDescription() {
            return "encrypted storage file [" + path + "]";
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return openRead(path);
        }

        @Override
        public long contentLength() throws IOException {
            return plainLength(path);
        }

        @Override
        public String getFilename() {
            return path.getFileName() != null ? path.getFileName().toString() : null;
        }

        @Override
        public boolean exists() {
            return Files.exists(path);
        }

        @Override
        public boolean isReadable() {
            return Files.isReadable(path);
        }
    }

    /** 加密写流：首帧写头部，之后按 1 MiB 分块 GCM 加密。 */
    private static final class EncryptingOutputStream extends FilterOutputStream {
        private final byte[] fileKey;
        private final byte[] buffer = new byte[CHUNK_SIZE];
        private int pos;
        private long nonceCounter;

        EncryptingOutputStream(OutputStream raw, byte[] masterKey, long plainSize) throws IOException {
            super(raw);
            this.fileKey = new byte[32];
            RANDOM.nextBytes(fileKey);
            this.nonceCounter = RANDOM.nextLong() & Long.MAX_VALUE;
            writeHeader(raw, masterKey, plainSize);
        }

        private void writeHeader(OutputStream raw, byte[] masterKey, long plainSize) throws IOException {
            try {
                byte[] nonce = new byte[12];
                RANDOM.nextBytes(nonce);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(masterKey, "AES"),
                        new GCMParameterSpec(GCM_TAG_BITS, nonce));
                byte[] ct = cipher.doFinal(fileKey);
                byte[] header = new byte[HEADER_SIZE];
                ByteBuffer buf = ByteBuffer.wrap(header);
                buf.put(MAGIC.getBytes(StandardCharsets.UTF_8));
                buf.putLong(plainSize);
                buf.put(nonce);
                buf.put(ct);
                buf.putInt(CHUNK_SIZE);
                raw.write(header);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("[IronWall] storage encrypt init failed", e);
            }
        }

        @Override
        public void write(int b) throws IOException {
            buffer[pos++] = (byte) b;
            if (pos == buffer.length) {
                flushChunk();
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (len <= 0) {
                return;
            }
            int remaining = len;
            int offset = off;
            while (remaining > 0) {
                int room = buffer.length - pos;
                int take = Math.min(room, remaining);
                System.arraycopy(b, offset, buffer, pos, take);
                pos += take;
                offset += take;
                remaining -= take;
                if (pos == buffer.length) {
                    flushChunk();
                }
            }
        }

        private void flushChunk() throws IOException {
            if (pos <= 0) {
                return;
            }
            try {
                byte[] nonce = new byte[12];
                ByteBuffer nb = ByteBuffer.wrap(nonce);
                nb.putLong(nonceCounter++);
                nb.putInt(0);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKey, "AES"),
                        new GCMParameterSpec(GCM_TAG_BITS, nonce));
                byte[] ct = cipher.doFinal(buffer, 0, pos);
                byte[] frame = new byte[4 + 12 + ct.length];
                ByteBuffer fb = ByteBuffer.wrap(frame);
                fb.putInt(pos);
                fb.put(nonce);
                fb.put(ct);
                out.write(frame);
                pos = 0;
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("[IronWall] storage encrypt chunk failed", e);
            }
        }

        @Override
        public void close() throws IOException {
            try {
                flushChunk();
            } finally {
                super.close();
            }
        }
    }

    /** 解密读流：读头部解封装文件密钥，逐块 GCM 解密。 */
    private static final class DecryptingInputStream extends InputStream {
        private final InputStream raw;
        private final byte[] fileKey;
        private final int chunkSize;
        private long remaining;
        private final byte[] chunk;
        private int pos;
        private int len;

        DecryptingInputStream(InputStream raw, byte[] masterKey) throws IOException {
            this.raw = raw;
            byte[] header = raw.readNBytes(HEADER_SIZE);
            if (header.length < HEADER_SIZE) {
                raw.close();
                throw new IOException("[IronWall] truncated encrypted file header");
            }
            ByteBuffer buf = ByteBuffer.wrap(header);
            byte[] magic = new byte[MAGIC.length()];
            buf.get(magic);
            if (!MAGIC.equals(new String(magic, StandardCharsets.UTF_8))) {
                raw.close();
                throw new IOException("[IronWall] not an encrypted storage file");
            }
            this.remaining = buf.getLong();
            byte[] wrapNonce = new byte[12];
            buf.get(wrapNonce);
            byte[] wrapped = new byte[48];
            buf.get(wrapped);
            this.chunkSize = buf.getInt();
            if (chunkSize <= 0 || chunkSize > 64 * 1024 * 1024) {
                raw.close();
                throw new IOException("[IronWall] invalid chunk size");
            }
            this.chunk = new byte[chunkSize];
            this.pos = 0;
            this.len = 0;
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(masterKey, "AES"),
                        new GCMParameterSpec(GCM_TAG_BITS, wrapNonce));
                byte[] plain = cipher.doFinal(wrapped);
                if (plain.length != 32) {
                    throw new IOException("[IronWall] invalid wrapped file key");
                }
                this.fileKey = plain;
            } catch (IOException e) {
                raw.close();
                throw e;
            } catch (Exception e) {
                raw.close();
                throw new IOException("[IronWall] file key unwrap failed", e);
            }
        }

        @Override
        public int read() throws IOException {
            if (pos >= len && !loadNextChunk()) {
                return -1;
            }
            return chunk[pos++] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            int total = 0;
            while (total < len) {
                if (pos >= this.len && !loadNextChunk()) {
                    break;
                }
                int take = Math.min(len - total, this.len - pos);
                System.arraycopy(chunk, pos, b, off + total, take);
                pos += take;
                total += take;
            }
            return total == 0 ? -1 : total;
        }

        private boolean loadNextChunk() throws IOException {
            if (remaining <= 0) {
                return false;
            }
            byte[] lenBuf = raw.readNBytes(4);
            if (lenBuf.length < 4) {
                throw new IOException("[IronWall] truncated encrypted file frame");
            }
            int frameLen = ByteBuffer.wrap(lenBuf).getInt();
            if (frameLen <= 0 || frameLen > chunkSize) {
                throw new IOException("[IronWall] invalid encrypted frame length");
            }
            byte[] nonce = raw.readNBytes(12);
            if (nonce.length < 12) {
                throw new IOException("[IronWall] truncated encrypted nonce");
            }
            byte[] ct = raw.readNBytes(frameLen + GCM_TAG_BITS / 8);
            if (ct.length < frameLen + GCM_TAG_BITS / 8) {
                throw new IOException("[IronWall] truncated encrypted frame");
            }
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(fileKey, "AES"),
                        new GCMParameterSpec(GCM_TAG_BITS, nonce));
                byte[] plain = cipher.doFinal(ct);
                System.arraycopy(plain, 0, chunk, 0, plain.length);
                this.len = plain.length;
                this.pos = 0;
                this.remaining -= plain.length;
                return true;
            } catch (Exception e) {
                throw new IOException("[IronWall] storage frame decrypt failed", e);
            }
        }

        @Override
        public void close() throws IOException {
            raw.close();
        }
    }
}