/*
 * lwma.c —— LWMA-1 难度调整（target 形式，逐块）
 *
 * 与 Bitcoin 的 2016 块周期调整不同，Ditcoin 每个块都按最近 N=45 个块
 * 的加权平均出块间隔调整难度；这是链级共识创新之一。
 *
 * 参考伪代码（规范已实测复核）：
 *   k = (N+1)*T/2                       // 45+1 个间隔的三角权重和
 *   prev = ts[0]
 *   L=0 ; sumTarget=0
 *   for i in 1..N:
 *       cur = max(ts[i], prev+1)        // 强制时间戳单调
 *       L += i * min(6T, cur - prev)    // 单块间隔上限 6T，防时间戳跳跃
 *       prev = cur ; sumTarget += target[i]
 *   L = max(L, N*k/3)                   // 下限，防难度无限上升
 *   next = L * sumTarget / (k*N*N)
 *
 * 数值边界：
 *   L ≤ Σ i*6T = 6T*N(N+1)/2 ≈ 2^22，sumTarget ≤ N*powLimit ≈ 2^230，
 *   乘积约 2^252，仍在 256 位内，不会触发饱和。
 */
#include "dtc/consensus.h"

#include <string.h>

bool dtc_lwma_next_target(const dtc_chain_params *p, const int64_t *times,
                          size_t n_times, const dtc_u256 *targets,
                          size_t n_targets, dtc_u256 *out)
{
    if (p == NULL || times == NULL || targets == NULL || out == NULL) {
        return false;
    }

    const size_t n = (size_t)p->lwma_window;
    if (n_times != n + 1 || n_targets != n) {
        return false;
    }

    const int64_t t = p->target_spacing;
    const int64_t k = ((int64_t)n + 1) * t / 2;
    const int64_t max_step = 6 * t;

    /* times[0] 是窗口前一个块，因此第一个区间即 times[1]-times[0] */
    int64_t prev = times[0];
    int64_t weighted = 0;

    dtc_u256 sum_target;
    dtc_u256_zero(&sum_target);

    for (size_t i = 1; i <= n; ++i) {
        int64_t cur = (times[i] > prev) ? times[i] : prev + 1;
        int64_t diff = cur - prev;
        if (diff > max_step) {
            diff = max_step;
        }
        weighted += (int64_t)i * diff;
        prev = cur;

        if (dtc_u256_add(&sum_target, &sum_target, &targets[i - 1])) {
            /* 窗口目标之和超过 2^256：输入非法，直接拒绝 */
            return false;
        }
    }

    /* 加权时长的下限：N*k/3 = 45*13800/3 = 207000 */
    int64_t min_weighted = (int64_t)n * k / 3;
    if (weighted < min_weighted) {
        weighted = min_weighted;
    }

    /* next = weighted * sumTarget / (k * N * N) */
    dtc_u256 scaled;
    (void)dtc_u256_mul_u64(&scaled, &sum_target, (uint64_t)weighted);

    uint64_t denom = (uint64_t)k * (uint64_t)n * (uint64_t)n;
    dtc_u256 next;
    if (!dtc_u256_div_u64(&next, &scaled, denom, NULL)) {
        return false;
    }

    /* 裁剪到 powLimit：难度不可能低于链的初始目标 */
    dtc_u256 limit;
    if (dtc_chain_pow_limit(p, &limit) && dtc_u256_cmp(&next, &limit) > 0) {
        next = limit;
    }

    *out = next;
    return true;
}
