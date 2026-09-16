package com.jdy.cloud.controller;

import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.security.ShareDownloadLimiter;
import com.jdy.cloud.security.ShareLinkSigner;
import com.jdy.cloud.security.ShareLookupLimiter;
import com.jdy.cloud.security.SharePasswordLimiter;
import com.jdy.cloud.security.StorageCryptoService;
import com.jdy.cloud.service.PasswordGuardService;
import com.jdy.cloud.service.ShareService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.AbstractResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IronWall v1.47.2: share download Range/206 regression tests
 * (report item). Real ShareController + MockMvc end-to-end:
 * no Range -> 200 full body
 * single Range -> 206 + Content-Range + Content-Length
 * unsatisfiable Range -> 416 plus Content-Range bytes-star-slash-N
 * encrypted resource (AbstractResource branch) -> 206 as well
 * zip download without Range -> 200 full body
 */
@ExtendWith(MockitoExtension.class)
class ShareDownloadRangeTest {

    @Mock private ShareService shareService;
    @Mock private ShareRepository shareRepository;
    @Mock private FileRepository fileRepository;
    @Mock private FolderRepository folderRepository;
    @Mock private PasswordGuardService passwordGuardService;
    @Mock private SharePasswordLimiter sharePasswordLimiter;
    @Mock private ShareLookupLimiter shareLookupLimiter;
    @Mock private ShareDownloadLimiter shareDownloadLimiter;
    @Mock private ShareLinkSigner shareLinkSigner;
    @Mock private StorageCryptoService storageCrypto;

    private ShareController controller;
    private MockMvc mockMvc;
    private Path tempDir;

    private static final byte[] PAYLOAD = "hello-world".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() throws Exception {
        controller = new ShareController(shareService, shareRepository, fileRepository,
                folderRepository, passwordGuardService, sharePasswordLimiter, shareLookupLimiter,
                shareDownloadLimiter, shareLinkSigner, storageCrypto);
        tempDir = Files.createTempDirectory("share-range-");
        ReflectionTestUtils.setField(controller, "uploadDir", tempDir.toString());
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
        Files.write(tempDir.resolve("range-test.bin"), PAYLOAD);
    }

    private void stubSingleFile() {
        FileEntity entity = new FileEntity();
        entity.setId(70L);
        entity.setFilename("range-test.bin");
        entity.setOriginalName("range-test.bin");
        when(shareService.downloadSharedFile("rangecode", null, null, null, null)).thenReturn(entity);
        when(storageCrypto.resourceOf(any(Path.class)))
                .thenAnswer(inv -> new FileSystemResource((Path) inv.getArgument(0)));
    }

    @Test
    void downloadWithoutRange_shouldReturn200FullBody() throws Exception {
        stubSingleFile();
        mockMvc.perform(get("/api/shares/download/rangecode"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Length", String.valueOf(PAYLOAD.length)))
                .andExpect(content().bytes(PAYLOAD));
    }

    @Test
    void downloadWithRange_shouldReturn206WithContentRange() throws Exception {
        stubSingleFile();
        mockMvc.perform(get("/api/shares/download/rangecode").header("Range", "bytes=0-4"))
                .andExpect(status().isPartialContent())
                .andExpect(header().string("Content-Range", "bytes 0-4/" + PAYLOAD.length))
                .andExpect(header().string("Content-Length", "5"))
                .andExpect(content().bytes("hello".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void downloadWithSuffixRange_shouldReturn206() throws Exception {
        stubSingleFile();
        mockMvc.perform(get("/api/shares/download/rangecode").header("Range", "bytes=6-10"))
                .andExpect(status().isPartialContent())
                .andExpect(header().string("Content-Range", "bytes 6-10/" + PAYLOAD.length))
                .andExpect(header().string("Content-Length", "5"))
                .andExpect(content().bytes("world".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void downloadWithUnsatisfiableRange_shouldReturn416() throws Exception {
        stubSingleFile();
        mockMvc.perform(get("/api/shares/download/rangecode").header("Range", "bytes=100-200"))
                .andExpect(status().isRequestedRangeNotSatisfiable())
                .andExpect(header().string("Content-Range", "bytes */" + PAYLOAD.length));
    }

    @Test
    void encryptedResource_withRange_shouldReturn206() throws Exception {
        FileEntity entity = new FileEntity();
        entity.setId(70L);
        entity.setFilename("range-test.bin");
        entity.setOriginalName("range-test.bin");
        when(shareService.downloadSharedFile("rangecode", null, null, null, null)).thenReturn(entity);
        when(storageCrypto.resourceOf(any(Path.class)))
                .thenAnswer(inv -> new ByteArrayBackedResource((Path) inv.getArgument(0), PAYLOAD));

        mockMvc.perform(get("/api/shares/download/rangecode").header("Range", "bytes=0-4"))
                .andExpect(status().isPartialContent())
                .andExpect(header().string("Content-Range", "bytes 0-4/" + PAYLOAD.length))
                .andExpect(header().string("Content-Length", "5"))
                .andExpect(content().bytes("hello".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void zipDownloadWithoutRange_shouldReturn200FullBody() throws Exception {
        when(shareService.downloadSharedFolderAsZip("zipcode", null, null, null))
                .thenReturn(PAYLOAD.clone());
        assertNotNull(controller);

        mockMvc.perform(get("/api/shares/download-zip/zipcode"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Length", String.valueOf(PAYLOAD.length)))
                .andExpect(content().bytes(PAYLOAD));
    }

    /** Encrypted-like streaming resource (non FileSystemResource) to verify the Range branch. */
    private static final class ByteArrayBackedResource extends AbstractResource {
        private final Path path;
        private final byte[] data;

        ByteArrayBackedResource(Path path, byte[] data) {
            this.path = path;
            this.data = data;
        }

        @Override
        public String getDescription() {
            return "encrypted-like resource [" + path + "]";
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(data);
        }

        @Override
        public long contentLength() {
            return data.length;
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
}