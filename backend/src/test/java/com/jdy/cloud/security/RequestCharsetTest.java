package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.18: 字符集解析 / 三族分类 / BOM 剥离契约测试。
 */
class RequestCharsetTest {

    @Test
    void extractCharsetShouldHandlePlainQuotedAndMissingForms() {
        assertEquals("utf-8", RequestCharset.extractCharset("application/json; charset=utf-8"));
        assertEquals("UTF-16LE", RequestCharset.extractCharset("application/json; charset=UTF-16LE"));
        assertEquals("utf-32", RequestCharset.extractCharset("application/json; charset=\"utf-32\""));
        assertEquals("gbk", RequestCharset.extractCharset("text/plain;charset=gbk; boundary=x"));
        assertNull(RequestCharset.extractCharset("application/json"));
        assertNull(RequestCharset.extractCharset(null));
    }

    @Test
    void classifyShouldMapSafeAnomalousAndRejectFamilies() {
        assertEquals(RequestCharset.Family.SAFE, RequestCharset.classify("UTF-8"));
        assertEquals(RequestCharset.Family.SAFE, RequestCharset.classify("GBK"));
        assertEquals(RequestCharset.Family.SAFE, RequestCharset.classify("gb2312"));
        assertEquals(RequestCharset.Family.SAFE, RequestCharset.classify("iso-8859-1"));
        assertEquals(RequestCharset.Family.SAFE, RequestCharset.classify(null));
        assertEquals(RequestCharset.Family.ANOMALOUS, RequestCharset.classify("UTF-16"));
        assertEquals(RequestCharset.Family.ANOMALOUS, RequestCharset.classify("UTF-16LE"));
        assertEquals(RequestCharset.Family.ANOMALOUS, RequestCharset.classify("UTF-16BE"));
        assertEquals(RequestCharset.Family.ANOMALOUS, RequestCharset.classify("UTF-32"));
        assertEquals(RequestCharset.Family.REJECT, RequestCharset.classify("UTF-7"));
        assertEquals(RequestCharset.Family.REJECT, RequestCharset.classify("KOI8-R"));
    }

    @Test
    void decodeShouldRoundTripUtf16LeAndStripBom() {
        String payload = "{\"u\":\"' OR 1=1 --\"}";
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_16LE);
        assertEquals(payload, RequestCharset.decode(bytes, "UTF-16LE"));

        byte[] withBom = new byte[bytes.length + 2];
        withBom[0] = (byte) 0xFF;
        withBom[1] = (byte) 0xFE;
        System.arraycopy(bytes, 0, withBom, 2, bytes.length);
        assertEquals(payload, RequestCharset.decode(withBom, "UTF-16LE"));
    }

    @Test
    void decodeShouldRoundTripUtf32() {
        String payload = "' OR 1=1 --";
        byte[] bytes = payload.getBytes(java.nio.charset.Charset.forName("UTF-32LE"));
        assertEquals(payload, RequestCharset.decode(bytes, "UTF-32LE"));
    }

    @Test
    void sniffBomCharsetShouldDetectUtf16AndUtf32Boms() {
        byte[] utf16leBom = new byte[] {(byte) 0xFF, (byte) 0xFE, 0x3C, 0x00};
        assertEquals("UTF-16LE", RequestCharset.sniffBomCharset(utf16leBom));
        byte[] utf16beBom = new byte[] {(byte) 0xFE, (byte) 0xFF, 0x00, 0x3C};
        assertEquals("UTF-16BE", RequestCharset.sniffBomCharset(utf16beBom));
        byte[] utf32leBom = new byte[] {(byte) 0xFF, (byte) 0xFE, 0x00, 0x00, 0x3C};
        assertEquals("UTF-32LE", RequestCharset.sniffBomCharset(utf32leBom));
        byte[] utf32beBom = new byte[] {0x00, 0x00, (byte) 0xFE, (byte) 0xFF, 0x00};
        assertEquals("UTF-32BE", RequestCharset.sniffBomCharset(utf32beBom));
        byte[] utf8Bom = new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 0x7B};
        assertEquals("UTF-8", RequestCharset.sniffBomCharset(utf8Bom));
        assertNull(RequestCharset.sniffBomCharset(new byte[] {0x7B, 0x22}));
        assertNull(RequestCharset.sniffBomCharset(null));
    }

    @Test
    void decodeShouldRoundTripGbkAndLatinAliases() {
        String payload = "x' OR 1=1 --";
        assertEquals(payload, RequestCharset.decode(payload.getBytes(java.nio.charset.Charset.forName("GBK")), "GBK"));
        byte[] latin = payload.getBytes(StandardCharsets.ISO_8859_1);
        assertEquals(payload, RequestCharset.decode(latin, "latin1"));
        assertNull(RequestCharset.decode(payload.getBytes(StandardCharsets.UTF_8), "no-such-charset-xyz"));
    }
}