package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.41.0: 路由表契约测试。
 * 1) 路由码为唯一 64 位小写 hex；2) 静态/动态模板还原与占位符校验；
 * 3) 与前端 scripts/route-table.json 双端同源一致性（防止两端漂移）。
 */
class ApiRouteTableTest {

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");
    private final ApiRouteTable table = new ApiRouteTable();

    @Test
    void codes_areUniqueLowerHex64() {
        RuleAssumptions.requireRule("api.routes");
        Set<String> codes = new HashSet<>();
        for (String[] entry : ApiRouteTable.entries()) {
            String code = ApiRouteTable.codeOf(entry[0]);
            assertTrue(HEX64.matcher(code).matches(), "非 64 位 hex 路由码: " + entry[0]);
            assertTrue(codes.add(code), "路由码冲突: " + entry[0]);
        }
    }

    @Test
    void staticTemplate_resolvesWithoutSegments() {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("auth/login");
        assertTrue(table.isCode(code));
        assertEquals("/api/auth/login", table.resolve(code, List.of()));
    }

    @Test
    void dynamicTemplate_resolvesWithSegments() {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("files/download/{0}");
        assertEquals("/api/files/download/12345", table.resolve(code, List.of("12345")));
    }

    @Test
    void challengeRoute_resolvesAndIsAnonTier() {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("shares/challenge/{0}");
        assertTrue(table.isCode(code));
        assertEquals("/api/shares/challenge/abc123", table.resolve(code, List.of("abc123")));
        assertEquals(ApiRouteTable.TIER_ANON, ApiRouteTable.tierOf("shares/challenge/{0}"));
    }

    @Test
    void dynamicTemplate_segmentMismatch_returnsNull() {
        RuleAssumptions.requireRule("api.routes");
        String code = ApiRouteTable.codeOf("files/download/{0}");
        assertNull(table.resolve(code, List.of()), "缺段应拒绝");
        assertNull(table.resolve(code, List.of("1", "extra")), "多段应拒绝");
        assertNull(table.resolve(code, List.of("")), "空段应拒绝");
    }

    @Test
    void unknownCode_isNotARouteCode() {
        RuleAssumptions.requireRule("api.routes");
        assertFalse(table.isCode("auth/login"));
        assertFalse(table.isCode("deadbeef"));
        assertNull(table.resolve("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", List.of()));
    }

    @Test
    void rotatedCode_acceptsCurrentAndLegacySalt() {
        RuleAssumptions.requireRule("api.routes");
        String current = table.currentSalt();
        assertNotNull(current);
        String rotated = ApiRouteTable.codeOf("auth/login", current);
        assertFalse(rotated.equals(ApiRouteTable.codeOf("auth/login")), "轮换码不应等于无盐旧码");
        assertTrue(table.isCode(rotated), "当期盐路由码应被接受");
        assertEquals("/api/auth/login", table.resolve(rotated, List.of()));
        assertTrue(table.activeSalts().contains(current), "activeSalts 应包含当期盐");
        assertTrue(table.activeSalts().contains(""), "activeSalts 应保留无盐旧码通道");
    }

    @Test
    void codeMap_translatesLegacyToCurrent() {
        RuleAssumptions.requireRule("api.routes");
        Map<String, String> codeMap = table.codeMap(ApiRouteTable.TIER_ANON);
        String legacy = ApiRouteTable.codeOf("auth/login");
        String current = ApiRouteTable.codeOf("auth/login", table.currentSalt());
        assertEquals(current, codeMap.get(legacy), "无盐旧码应翻译为当期码");
    }

    @Test
    void routeMap_tierFiltering_hidesAdminFromAnon() {
        RuleAssumptions.requireRule("api.routes");
        Map<String, String> anon = table.routeMap(ApiRouteTable.TIER_ANON);
        Map<String, String> admin = table.routeMap(ApiRouteTable.TIER_ADMIN);
        assertFalse(anon.values().stream().anyMatch(p -> p.startsWith("/api/admin")),
                "匿名层不应下发管理面路径");
        assertTrue(admin.values().stream().anyMatch(p -> p.startsWith("/api/admin")),
                "管理层应包含管理面路径");
        assertTrue(admin.size() > anon.size(), "管理层路由地图应大于匿名层");
    }

    @Test
    void routeMap_matchesFrontendRouteTableJson() throws Exception {
        RuleAssumptions.requireRule("api.routes");
        // 双端同源：src/test/resources/security/route-table.json 与前端 scripts/route-table.json 内容一致
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("security/route-table.json")) {
            assertNotNull(in, "route-table.json 缺失");
            Map<?, ?> json = mapper.readValue(in, Map.class);
            List<?> routes = (List<?>) json.get("routes");
            List<String[]> expected = new ArrayList<>();
            for (Object item : routes) {
                Map<?, ?> r = (Map<?, ?>) item;
                expected.add(new String[]{String.valueOf(r.get("logical")), String.valueOf(r.get("real"))});
            }
            List<String[]> actual = ApiRouteTable.entries();
            assertEquals(expected.size(), actual.size(), "前后端路由条目数量不一致");
            for (int i = 0; i < expected.size(); i++) {
                assertEquals(expected.get(i)[0], actual.get(i)[0], "logical 不一致");
                assertEquals(expected.get(i)[1], actual.get(i)[1], "real 不一致");
            }
            for (String[] entry : expected) {
                assertEquals(ApiRouteTable.codeOf(entry[0]), codeFromTable(expected, entry[0]), "路由码算法不一致");
            }
        }
    }

    private String codeFromTable(List<String[]> entries, String logical) {
        for (String[] e : entries) {
            if (e[0].equals(logical)) {
                return ApiRouteTable.codeOf(logical);
            }
        }
        return null;
    }
}
