/*
 * config.h —— 编译期策略开关（不属于链参数的共识数值，故不进 params.c）
 */
#ifndef DTC_CONFIG_H
#define DTC_CONFIG_H

/*
 * sighash 域分离开关（SPEC「补丁 1」）：
 *   0 = legacy / segwit-v0 沿用 Bitcoin 原算法（默认，跨链重放安全性完全
 *       依赖创世块唯一性 —— 见 README 声明一）
 *   1 = 在待哈希消息前拼接 MAGIC_MAIN 的 4 字节小端表示
 *
 * ★ 任何修改都必须重新生成全部 sighash 冻结向量；测试
 *   test_sighash_domain_switch 会分别验证两种模式，且要求可用编译选项
 *   -DDTC_SIGHASH_DOMAIN_SEP=1 重新构建后测试仍然通过。
 */
#ifndef DTC_SIGHASH_DOMAIN_SEP
#define DTC_SIGHASH_DOMAIN_SEP 0
#endif

#if (DTC_SIGHASH_DOMAIN_SEP != 0) && (DTC_SIGHASH_DOMAIN_SEP != 1)
#error "DTC_SIGHASH_DOMAIN_SEP 只能取 0 或 1"
#endif

#endif /* DTC_CONFIG_H */
