package com.jdy.cloud.security;

import org.junit.jupiter.api.Assumptions;

/**
 * 规则集准入判断。
 *
 * <p>检测规则由 {@code config/ironwall-rules.sample.json} 或部署者自备的规则集提供，
 * 未配置的规则族可以照常缺席。依赖某条规则的用例若照跑必红，
 * 而红的原因是「这条规则还没配」，不是代码坏了——因此统一在此做准入判断：
 * 规则在就验证行为，规则不在就跳过，并在测试报告里写明原因。
 *
 * <p>规则集完整时全部用例照常执行，覆盖率不下降。
 */
final class RuleAssumptions {

    private RuleAssumptions() {
    }

    /** 该规则条目未配置时跳过当前用例。 */
    static void requireRule(String key) {
        Assumptions.assumeTrue(IronWallRules.has(key),
                () -> "跳过：未配置规则条目 " + key + "，对应检测族当前停用");
    }

    /** 规则集不完整时跳过当前用例（用于横跨多个规则族的用例）。 */
    static void requireCompleteRuleSet() {
        Assumptions.assumeTrue(IronWallRules.missingKeys().isEmpty(),
                () -> "跳过：当前规则集不完整，缺失 " + IronWallRules.missingKeys());
    }
}
