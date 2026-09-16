package com.jdy.cloud.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SecurityUtilsTest {

    @Test
    void containsXss_shouldDetectScriptTag() {
        assertTrue(SecurityUtils.containsXss("<script>alert('xss')</script>"));
        assertTrue(SecurityUtils.containsXss("javascript:void(0)"));
        assertTrue(SecurityUtils.containsXss("<iframe src='evil.com'>"));
        assertTrue(SecurityUtils.containsXss("onclick='alert(1)'"));
    }

    @Test
    void containsXss_shouldPassSafeInput() {
        assertFalse(SecurityUtils.containsXss("hello world"));
        assertFalse(SecurityUtils.containsXss("user@example.com"));
        assertFalse(SecurityUtils.containsXss("safe text with <b> html tags"));
        assertFalse(SecurityUtils.containsXss(null));
    }

    @Test
    void sanitizeHtml_shouldEscapeDangerousChars() {
        assertEquals("&lt;script&gt;", SecurityUtils.sanitizeHtml("<script>"));
        assertEquals("&amp;", SecurityUtils.sanitizeHtml("&"));
        assertEquals("&quot;hello&quot;", SecurityUtils.sanitizeHtml("\"hello\""));
    }

    @Test
    void isValidUsername_shouldValidateCorrectly() {
        assertTrue(SecurityUtils.isValidUsername("testuser"));
        assertTrue(SecurityUtils.isValidUsername("user_123"));
        assertTrue(SecurityUtils.isValidUsername("用户名"));
        assertFalse(SecurityUtils.isValidUsername("ab"));
        assertFalse(SecurityUtils.isValidUsername("<script>"));
        assertFalse(SecurityUtils.isValidUsername(null));
    }

    @Test
    void isValidEmail_shouldValidateCorrectly() {
        assertTrue(SecurityUtils.isValidEmail("test@example.com"));
        assertTrue(SecurityUtils.isValidEmail("user.name+tag@domain.co.uk"));
        assertFalse(SecurityUtils.isValidEmail("not-email"));
        assertFalse(SecurityUtils.isValidEmail("@domain.com"));
        assertFalse(SecurityUtils.isValidEmail(null));
    }

    @Test
    void isValidFilename_shouldBlockPathTraversal() {
        assertTrue(SecurityUtils.isValidFilename("document.txt"));
        assertTrue(SecurityUtils.isValidFilename("my file (1).pdf"));
        assertFalse(SecurityUtils.isValidFilename("../etc/passwd"));
        assertFalse(SecurityUtils.isValidFilename("file/name.txt"));
        assertFalse(SecurityUtils.isValidFilename("..\\..\\windows"));
        assertFalse(SecurityUtils.isValidFilename(""));
        assertFalse(SecurityUtils.isValidFilename(null));
    }

    @Test
    void isStrongPassword_shouldValidateStrength() {
        assertTrue(SecurityUtils.isStrongPassword("Abc@1234"));
        assertTrue(SecurityUtils.isStrongPassword("MyP@ssw0rd!"));
        assertFalse(SecurityUtils.isStrongPassword("12345678"));
        assertFalse(SecurityUtils.isStrongPassword("abcdefgh"));
        assertFalse(SecurityUtils.isStrongPassword("Abcdefgh"));
        assertTrue(SecurityUtils.isStrongPassword("Abc12345"));
        assertTrue(SecurityUtils.isStrongPassword("NoSpecial1"));
        assertTrue(SecurityUtils.isStrongPassword("short1A@"));
        assertFalse(SecurityUtils.isStrongPassword(null));
    }

    @Test
    void isPathTraversalSafe_shouldDetectAttacks() {
        assertTrue(SecurityUtils.isPathTraversalSafe("uploads/file.txt"));
        assertFalse(SecurityUtils.isPathTraversalSafe("../etc/passwd"));
        assertFalse(SecurityUtils.isPathTraversalSafe("..\\windows"));
        assertFalse(SecurityUtils.isPathTraversalSafe("file\0hidden.txt"));
    }

    @Test
    void safePageAndSize_shouldClampValues() {
        assertEquals(0, SecurityUtils.safePage(-1));
        assertEquals(10, SecurityUtils.safePage(10));
        assertEquals(1, SecurityUtils.safeSize(0));
        assertEquals(20, SecurityUtils.safeSize(20));
        assertEquals(100, SecurityUtils.safeSize(200));
    }

    @Test
    void isSafeUsername_shouldRejectHtmlAndControlChars() {
        assertTrue(SecurityUtils.isSafeUsername("testuser"));
        assertTrue(SecurityUtils.isSafeUsername("经典云网盘用户"));
        assertTrue(SecurityUtils.isSafeUsername("user.name 2026"));
        assertTrue(SecurityUtils.isSafeUsername("ab"));
        assertFalse(SecurityUtils.isSafeUsername("a"));
        assertFalse(SecurityUtils.isSafeUsername("<img src=x>"));
        assertFalse(SecurityUtils.isSafeUsername("<svg/onload=1>"));
        assertFalse(SecurityUtils.isSafeUsername("user<script>"));
        assertFalse(SecurityUtils.isSafeUsername(null));
    }

    @Test
    void stripHtmlTags_shouldRemoveTagsAndControlChars() {
        assertEquals("hello", SecurityUtils.stripHtmlTags("<b>hello</b>"));
        assertEquals("hello alert(1) world", SecurityUtils.stripHtmlTags("hello <script>alert(1)</script> world"));
        assertEquals("abc", SecurityUtils.stripHtmlTags("abc\u0000"));
        assertNull(SecurityUtils.stripHtmlTags(null));
    }

    @Test
    void reservedUsernames_shouldRejectImpersonationNames() {
        assertTrue(SecurityUtils.isReservedUsername("admin"));
        assertTrue(SecurityUtils.isReservedUsername(" ADMIN "));
        assertTrue(SecurityUtils.isReservedUsername("Root"));
        assertTrue(SecurityUtils.isReservedUsername("官方"));
        assertTrue(SecurityUtils.isReservedUsername("客服"));
        assertFalse(SecurityUtils.isReservedUsername("normaluser"));
        assertFalse(SecurityUtils.isReservedUsername("alice"));
        assertFalse(SecurityUtils.isReservedUsername(null));
    }
}
