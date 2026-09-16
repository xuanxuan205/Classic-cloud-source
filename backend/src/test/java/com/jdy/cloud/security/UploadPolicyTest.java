package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** IronWall v1.46.0: 上传策略单一数据源单元测试（check/upload/merge 共用 UploadPolicy）。 */
class UploadPolicyTest {

    /** IronWall v1.47.0: 白名单必须精确等于产品口径四类 27 个，防止名单悄悄漂移。 */
    @Test
    void normalUserWhitelist_isExactlyThe27ExtensionProductContract() {
        Set<String> expected = Set.of(
                "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv",
                "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg",
                "mp3", "wav", "flac", "mp4", "mov", "mkv", "avi",
                "zip", "7z", "rar");
        assertEquals(expected, UploadPolicy.NORMAL_USER_ALLOWED_EXTENSIONS);
    }

    /** IronWall v1.47.0: 27 个后缀逐一通过文件名策略校验。 */
    @Test
    void normalUser_eachOfThe27Extensions_passesFilenamePolicy() {
        for (String ext : UploadPolicy.NORMAL_USER_ALLOWED_EXTENSIONS) {
            assertDoesNotThrow(() -> UploadPolicy.validateFilename("file." + ext, false),
                    "白名单后缀 ." + ext + " 应放行");
        }
    }

    @Test
    void normalUser_legacyExtraExtensions_nowRejected() {
        // 历史宽松名单中的后缀全部收紧为产品口径 27 个
        for (String ext : new String[]{"epub", "mobi", "azw3", "ttf", "woff2", "tar", "gz", "conf", "lua", "json", "yml", "dwg", "brushset"}) {
            BusinessException ex = assertThrows(BusinessException.class,
                    () -> UploadPolicy.validateFilename("legacy." + ext, false), ext);
            assertEquals(ErrorCode.FILE_TYPE_NOT_ALLOWED.getCode(), ex.getCode());
        }
    }

    @Test
    void normalUser_allowedDocExtensions_pass() {
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("报告.pdf", false));
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("数据.xlsx", false));
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("笔记.md", false));
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("压缩包.zip", false));
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("音乐.mp3", false));
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("矢量图.svg", false));
    }

    @Test
    void normalUser_blockedExecutableExtension_rejected() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateFilename("tool.exe", false));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    @Test
    void normalUser_scriptExtension_rejected() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateFilename("payload.js", false));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    @Test
    void normalUser_unknownExtension_rejected() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateFilename("data.xyz123", false));
        assertEquals(ErrorCode.FILE_TYPE_NOT_ALLOWED.getCode(), ex.getCode());
        assertTrue(ex.getMessage().contains("不支持"));
    }

    /** IronWall v1.47.3: .bin is rejected with explicit business code 4002 . */
    @Test
    void normalUser_binExtension_rejectedWithFileTypeNotAllowed() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateFilename("payload.bin", false));
        assertEquals(ErrorCode.FILE_TYPE_NOT_ALLOWED.getCode(), ex.getCode());
    }

    @Test
    void normalUser_doubleExtensionSmuggle_htmlTxt_rejected() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateFilename("payload.html.txt", false));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        assertTrue(ex.getMessage().contains("多重扩展名"));
    }

    @Test
    void normalUser_doubleExtensionSmuggle_phpJpg_rejected() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateFilename("shell.php.jpg", false));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        assertTrue(ex.getMessage().contains("多重扩展名"));
    }

    @Test
    void normalUser_middleDangerSegment_rejected() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateFilename("a.js.txt", false));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    @Test
    void admin_anyExtension_passesFilenameCheck() {
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("tool.exe", true));
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("payload.html.txt", true));
        assertDoesNotThrow(() -> UploadPolicy.validateFilename("script.php", true));
    }

    @Test
    void anyUser_traversalOrIllegalName_rejected() {
        assertThrows(BusinessException.class, () -> UploadPolicy.validateFilename("../etc/passwd", true));
        assertThrows(BusinessException.class, () -> UploadPolicy.validateFilename("a/b.txt", true));
        assertThrows(BusinessException.class, () -> UploadPolicy.validateFilename("noext", true));
        assertThrows(BusinessException.class, () -> UploadPolicy.validateFilename("", true));
    }

    @Test
    void normalUser_directUpload_under10Mb_passes() {
        assertDoesNotThrow(() -> UploadPolicy.validateSize(10L * 1024 * 1024, false, true));
        assertDoesNotThrow(() -> UploadPolicy.validateSize(1L, false, true));
    }

    @Test
    void normalUser_directUpload_over10Mb_rejectedWithChunkHint() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateSize(10L * 1024 * 1024 + 1, false, true));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        assertTrue(ex.getMessage().contains("分片"));
    }

    @Test
    void normalUser_chunkedUpload_upTo850Mb_passes() {
        assertDoesNotThrow(() -> UploadPolicy.validateSize(850L * 1024 * 1024, false, false));
    }

    @Test
    void normalUser_over850Mb_rejectedFileTooLarge() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateSize(850L * 1024 * 1024 + 1, false, false));
        assertEquals(ErrorCode.FILE_TOO_LARGE.getCode(), ex.getCode());
    }

    @Test
    void admin_largeFileUpTo20Gb_passes() {
        assertDoesNotThrow(() -> UploadPolicy.validateSize(20L * 1024 * 1024 * 1024, true, false));
        assertDoesNotThrow(() -> UploadPolicy.validateSize(11L * 1024 * 1024, true, true));
    }

    @Test
    void admin_over20Gb_rejectedFileTooLarge() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> UploadPolicy.validateSize(20L * 1024 * 1024 * 1024 + 1, true, false));
        assertEquals(ErrorCode.FILE_TOO_LARGE.getCode(), ex.getCode());
    }

    @Test
    void zeroOrNegativeSize_rejected() {
        assertThrows(BusinessException.class, () -> UploadPolicy.validateSize(0L, false, false));
        assertThrows(BusinessException.class, () -> UploadPolicy.validateSize(-1L, true, false));
    }

    @Test
    void extensionOf_normalizesCase() {
        assertEquals("pdf", UploadPolicy.extensionOf("A.PDF"));
        assertEquals("txt", UploadPolicy.extensionOf("b.txt"));
        assertEquals("", UploadPolicy.extensionOf("noext"));
        assertEquals("", UploadPolicy.extensionOf(null));
    }
}