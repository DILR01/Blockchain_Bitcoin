/*
 * merkle.h —— Merkle 树与见证承诺
 *
 * 与 Bitcoin 相同的基础结构（这是刻意沿用，不属于链级创新）：
 *   * 叶子为 32 字节哈希；相邻两两拼接后 SHA256d；
 *   * 奇数个节点时复制最后一个（Bitcoin 的 CVE-2012-2459 语义也一并继承，
 *     由调用方在解析区块时做重复子树检查——当前 M1 尚未实现该检查）。
 */
#ifndef DTC_MERKLE_H
#define DTC_MERKLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * 计算 merkle root。hashes 为 n 个 32 字节哈希（自然字节序）。
 * n == 0 时返回全零（创世块 coinbase 单独一个叶子，因此不触发）。
 */
void dtc_merkle_root(const uint8_t (*hashes)[32], size_t n, uint8_t out[32]);

/*
 * 见证 merkle root：coinbase 的 wtxid 按规则以 32 个 0 替换。
 * 若 n == 0 也返回全零。
 */
void dtc_witness_merkle_root(const uint8_t (*wtxids)[32], size_t n,
                             uint8_t out[32]);

/*
 * 见证承诺：SHA256d(witness_root || reserved_value)。
 * coinbase 的 OP_RETURN 输出中必须携带该 32 字节承诺（前面固定 6 字节
 * 头 0xaa21a9ed）。
 */
void dtc_witness_commitment(const uint8_t witness_root[32],
                            const uint8_t reserved[32], uint8_t out[32]);

#endif /* DTC_MERKLE_H */
