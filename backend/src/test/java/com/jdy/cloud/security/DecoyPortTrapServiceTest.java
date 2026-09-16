package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 假端口陷阱：诱饵端口必须避开真实业务端口，包括部署者自定义的那些。 */
class DecoyPortTrapServiceTest {

    private static List<Integer> flatten(Map<Integer, List<Integer>> ports) {
        List<Integer> all = new ArrayList<>();
        ports.values().forEach(all::addAll);
        return all;
    }

    @Test
    void generatesSevenLayersWithoutDuplicates() {
        DecoyPortTrapService service = new DecoyPortTrapService("");

        Map<Integer, List<Integer>> ports = service.generate();
        List<Integer> all = flatten(ports);

        assertEquals(DecoyPortTrapService.LAYERS, ports.size());
        ports.values().forEach(layer -> assertEquals(3, layer.size(), "每层 3 个诱饵端口"));
        assertEquals(new HashSet<>(all).size(), all.size(), "诱饵端口之间不得重复");
    }

    @Test
    void avoidsCommonServicePorts() {
        DecoyPortTrapService service = new DecoyPortTrapService("");

        List<Integer> all = flatten(service.generate());

        for (int wellKnown : new int[]{22, 80, 443, 3306, 888, 8080}) {
            assertFalse(all.contains(wellKnown), "不得占用常见服务端口 " + wellKnown);
        }
        assertTrue(all.stream().allMatch(p -> p >= 31000 && p <= 64999), "诱饵端口应落在高位随机段");
    }

    @Test
    void honorsExtraReservedPortsFromConfig() {
        DecoyPortTrapService service = new DecoyPortTrapService("34567, 22022");

        for (int i = 0; i < 40; i++) {
            List<Integer> all = flatten(service.generate());
            assertFalse(all.contains(34567), "自定义保留端口 34567 不得被占用");
            assertFalse(all.contains(22022), "自定义保留端口 22022 不得被占用");
        }
    }

    @Test
    void ignoresMalformedReservedEntriesInsteadOfFailing() {
        DecoyPortTrapService service = new DecoyPortTrapService("  , abc , 0 , 70000 , 2222 ");

        List<Integer> all = flatten(service.generate());

        assertFalse(all.contains(2222), "合法的自定义端口应生效");
        assertEquals(DecoyPortTrapService.LAYERS, service.ports().size(), "非法片段不应影响生成");
    }

    @Test
    void layerLookupMatchesGeneratedPorts() {
        DecoyPortTrapService service = new DecoyPortTrapService("");

        Map<Integer, List<Integer>> ports = service.ports();
        Set<Integer> decoys = new HashSet<>(flatten(ports));

        for (Map.Entry<Integer, List<Integer>> e : ports.entrySet()) {
            for (Integer port : e.getValue()) {
                assertEquals(e.getKey(), service.layerOf(port), "诱饵端口应能查到所属层级");
            }
        }
        assertTrue(decoys.stream().allMatch(p -> service.layerOf(p) > 0));
        assertEquals(-1, service.layerOf(1), "非诱饵端口应返回 -1");
    }
}
