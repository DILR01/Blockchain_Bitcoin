/*
 * secp.h —— ECDSA 验签适配层（基于 vendored libsecp256k1）
 *
 * 设计原则（对应提示词硬约束 2）：
 *   * 绝不自己实现椭圆曲线或签名算法；所有曲线运算都交给
 *     vendor/secp256k1（版本 0.8.1，MIT）。
 *   * 本层只做「胶水」：把 secp256k1 的接口包装成脚本引擎要求的
 *     dtc_sig_checker vtable，并附加 Ditcoin 的编码约束。
 *
 * Ditcoin 从高度 0 起强制的签名编码规则（比 Bitcoin 策略层更严格）：
 *   * 公钥只接受 33 字节压缩或 65 字节非压缩两种 SEC 编码；
 *   * 签名必须是严格 DER（BIP66），且 S 值必须为低半区（low-S）；
 *   * 拒绝空签名、非规范 hashtype 由上层 sighash 检查负责。
 * 这样可以从共识层消除签名可塑性，代价是更少的兼容脚本面。
 */
#ifndef DTC_SECP_H
#define DTC_SECP_H

#include <stdbool.h>

#include "dtc/script.h"

/*
 * ECDSA 校验器句柄。
 * 调用方持有该结构体（不要拷贝），init 后把 iface 指针交给
 * dtc_script_ctx.checker 即可。
 */
typedef struct {
    void *impl;          /* 内部为 secp256k1_context*，故意不暴露头文件 */
    dtc_sig_checker iface; /* 供脚本引擎调用的函数指针表 */
} dtc_ecdsa_checker;

/*
 * 初始化校验器。返回 false 表示内存不足或上下文创建失败。
 * 每个进程/线程持有独立实例；不要并发共享同一实例做随机化操作。
 */
bool dtc_ecdsa_checker_init(dtc_ecdsa_checker *checker);

/* 释放内部上下文（可重复调用） */
void dtc_ecdsa_checker_destroy(dtc_ecdsa_checker *checker);

#endif /* DTC_SECP_H */
