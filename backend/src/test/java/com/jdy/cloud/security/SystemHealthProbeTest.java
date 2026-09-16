package com.jdy.cloud.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.37.0: CPU/堆水位采样器契约测试（tarpit 熔断信号源）。
 */
class SystemHealthProbeTest {

    @Test
    void healthyHost_shouldNotBeUnderPressure() {
        SystemHealthProbe probe = new SystemHealthProbe(0.8, 0.85, 0) {
            @Override protected double cpuLoad() { return 0.2; }
            @Override protected double heapUsedRatio() { return 0.4; }
        };
        assertFalse(probe.isUnderPressure());
    }

    @Test
    void cpuOverWatermark_shouldBeUnderPressure() {
        SystemHealthProbe probe = new SystemHealthProbe(0.8, 0.85, 0) {
            @Override protected double cpuLoad() { return 0.9; }
            @Override protected double heapUsedRatio() { return 0.1; }
        };
        assertTrue(probe.isUnderPressure());
    }

    @Test
    void heapOverWatermark_shouldBeUnderPressure() {
        SystemHealthProbe probe = new SystemHealthProbe(0.8, 0.85, 0) {
            @Override protected double cpuLoad() { return 0.1; }
            @Override protected double heapUsedRatio() { return 0.95; }
        };
        assertTrue(probe.isUnderPressure());
    }

    @Test
    void probeException_shouldFailOpenAsHealthy() {
        SystemHealthProbe probe = new SystemHealthProbe(0.8, 0.85, 0) {
            @Override protected double cpuLoad() { throw new RuntimeException("mxbean unavailable"); }
            @Override protected double heapUsedRatio() { return 0.1; }
        };
        assertFalse(probe.isUnderPressure());
    }

    @Test
    void sampleResult_shouldBeCachedWithinRefreshWindow() throws Exception {
        final boolean[] flag = { true };
        SystemHealthProbe probe = new SystemHealthProbe(0.8, 0.85, 200) {
            @Override protected double cpuLoad() { return flag[0] ? 0.95 : 0.1; }
            @Override protected double heapUsedRatio() { return 0.1; }
        };
        assertTrue(probe.isUnderPressure());
        flag[0] = false;
        assertTrue(probe.isUnderPressure(), "within refresh window the cached verdict must hold");
        Thread.sleep(260);
        assertFalse(probe.isUnderPressure(), "after refresh window a fresh sample must be taken");
    }

    @Test
    void invalidWatermarks_shouldFallBackToDefaults() {
        SystemHealthProbe zero = new SystemHealthProbe(0, 0, 0) {
            @Override protected double cpuLoad() { return 0.81; }
            @Override protected double heapUsedRatio() { return 0.1; }
        };
        assertTrue(zero.isUnderPressure(), "watermark 0 must fall back to default 0.8");

        SystemHealthProbe over = new SystemHealthProbe(2.0, 2.0, 0) {
            @Override protected double cpuLoad() { return 0.79; }
            @Override protected double heapUsedRatio() { return 0.1; }
        };
        assertFalse(over.isUnderPressure(), "watermark >1 must fall back to defaults");
    }
}
