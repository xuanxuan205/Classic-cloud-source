package com.jdy.cloud.security;

import com.sun.management.OperatingSystemMXBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;

/**
 * IronWall v1.37.0: CPU/内存水位采样器（tarpit 熔断信号源）。
 *
 * 采样结果按 refreshMs 缓存，避免高并发下每请求调用昂贵的 MXBean 探测；
 * 任一探测异常一律按「不高压」处理（fail-open），绝不让熔断器本身拖垮请求链。
 * cpuLoad()/heapUsedRatio() 为受保护方法，测试可覆写模拟任意水位。
 */
@Component
public class SystemHealthProbe {

    private static final double DEFAULT_CPU_WATERMARK = 0.8d;
    private static final double DEFAULT_HEAP_WATERMARK = 0.85d;
    private static final long DEFAULT_REFRESH_MS = 1000L;

    private final double cpuWatermark;
    private final double heapWatermark;
    private final long refreshMs;

    private volatile long lastSampleAt;
    private volatile boolean lastPressure;

    public SystemHealthProbe() {
        this(DEFAULT_CPU_WATERMARK, DEFAULT_HEAP_WATERMARK, DEFAULT_REFRESH_MS);
    }

    @Autowired
    public SystemHealthProbe(
            @Value("${app.security.defense-engine.tarpit.cpu-watermark:0.8}") double cpuWatermark,
            @Value("${app.security.defense-engine.tarpit.heap-watermark:0.85}") double heapWatermark,
            @Value("${app.security.defense-engine.tarpit.health-refresh-ms:1000}") long refreshMs) {
        this.cpuWatermark = sanitize(cpuWatermark, DEFAULT_CPU_WATERMARK);
        this.heapWatermark = sanitize(heapWatermark, DEFAULT_HEAP_WATERMARK);
        this.refreshMs = Math.max(0L, refreshMs);
    }

    private static double sanitize(double watermark, double fallback) {
        return watermark > 0 && watermark <= 1 ? watermark : fallback;
    }

    /** CPU 或堆内存任一超过水位线即视为高压。 */
    public boolean isUnderPressure() {
        long now = System.currentTimeMillis();
        if (now - lastSampleAt < refreshMs) {
            return lastPressure;
        }
        boolean pressure;
        try {
            pressure = cpuLoad() >= cpuWatermark || heapUsedRatio() >= heapWatermark;
        } catch (Exception e) {
            pressure = false;
        }
        lastPressure = pressure;
        lastSampleAt = now;
        return pressure;
    }

    /** 进程 CPU 负载（0~1）。探测失败或系统不提供时返回 0（不触发熔断）。 */
    protected double cpuLoad() {
        OperatingSystemMXBean bean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        double load = bean.getCpuLoad();
        return load < 0 ? 0 : load;
    }

    /** 堆内存使用率（0~1）。max<=0（无上限堆）时返回 0。 */
    protected double heapUsedRatio() {
        MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
        MemoryUsage heap = memory.getHeapMemoryUsage();
        long max = heap.getMax();
        if (max <= 0) {
            return 0;
        }
        return (double) heap.getUsed() / (double) max;
    }
}
