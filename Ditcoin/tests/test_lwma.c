/*
 * test_lwma.c —— LWMA-1 难度调整（target 形式）
 *
 * 数学约定（N=45，T=600）：
 *   k = (N+1)*T/2 = 13800
 *   L = Σ i*min(6T, delta_i)
 *   next = max(L, N*k/3) * Σtarget / (k*N*N)
 */
#include "test_util.h"

#include "dtc/consensus.h"

#define DTC_N 45

/* 用固定间隔构造时间戳与目标，返回下一目标 */
static bool run_lwma(int64_t interval, const dtc_u256 *target, dtc_u256 *out)
{
    int64_t times[DTC_N + 1];
    dtc_u256 targets[DTC_N];
    /* times[0] 为窗口前一个块的时间，之后每块间隔 interval 秒 */
    for (size_t i = 0; i <= DTC_N; ++i) {
        times[i] = (int64_t)i * interval;
    }
    for (size_t i = 0; i < DTC_N; ++i) {
        targets[i] = *target;
    }
    return dtc_lwma_next_target(&dtc_chain_main, times, DTC_N + 1, targets,
                                DTC_N, out);
}

void test_lwma(void)
{
    dtc_u256 limit;
    CHECK(dtc_chain_pow_limit(&dtc_chain_main, &limit));

    test_group("稳态：间隔 600 秒 → 目标不变");
    {
        dtc_u256 t0, next;
        uint64_t rem = 0;
        CHECK(dtc_u256_div_u64(&t0, &limit, 16, &rem));
        CHECK(run_lwma(600, &t0, &next));
        CHECK(dtc_u256_equal(&t0, &next));
    }

    test_group("出块过快：间隔 200 秒 → 目标变为 1/3");
    {
        dtc_u256 t0, next, expect;
        uint64_t rem = 0;
        CHECK(dtc_u256_div_u64(&t0, &limit, 16, &rem));
        CHECK(run_lwma(200, &t0, &next));
        CHECK(dtc_u256_div_u64(&expect, &t0, 3, &rem));
        CHECK(rem == 0);
        CHECK(dtc_u256_equal(&next, &expect));
    }

    test_group("出块过慢：间隔 1800 秒 → 目标变为 3 倍");
    {
        dtc_u256 t0, next, expect;
        uint64_t rem = 0;
        CHECK(dtc_u256_div_u64(&t0, &limit, 16, &rem));
        CHECK(run_lwma(1800, &t0, &next));
        CHECK(dtc_u256_mul_u64(&expect, &t0, 3) == false);
        CHECK(dtc_u256_equal(&next, &expect));
    }

    test_group("裁剪到 powLimit");
    {
        dtc_u256 next;
        CHECK(run_lwma(1800, &limit, &next));
        CHECK(dtc_u256_equal(&next, &limit));
    }

    test_group("间隔上限被裁剪到 6T");
    {
        /* 1800 与 36000 秒应得到相同结果（min(6T, delta) 生效） */
        dtc_u256 t0, a, b;
        uint64_t rem = 0;
        CHECK(dtc_u256_div_u64(&t0, &limit, 16, &rem));
        CHECK(run_lwma(1800, &t0, &a));
        CHECK(run_lwma(36000, &t0, &b));
        CHECK(dtc_u256_equal(&a, &b));
    }

    test_group("乱序/非单调时间戳（强制 +1 单调）");
    {
        int64_t times[DTC_N + 1];
        dtc_u256 targets[DTC_N];
        dtc_u256 t0, out;
        uint64_t rem = 0;
        CHECK(dtc_u256_div_u64(&t0, &limit, 16, &rem));
        for (size_t i = 0; i <= DTC_N; ++i) {
            /* 故意制造回退：后半段时间戳回到 0 */
            times[i] = (i <= 20) ? (int64_t)i * 600 : 0;
        }
        for (size_t i = 0; i < DTC_N; ++i) {
            targets[i] = t0;
        }
        CHECK(dtc_lwma_next_target(&dtc_chain_main, times, DTC_N + 1, targets,
                                   DTC_N, &out));
        /* 结果必须非零且不超过 powLimit */
        CHECK(!dtc_u256_is_zero(&out));
        CHECK(dtc_u256_cmp(&out, &limit) <= 0);
    }

    test_group("参数校验");
    {
        int64_t times[4] = {0, 600, 1200, 1800};
        dtc_u256 targets[3];
        dtc_u256 out;
        dtc_u256_set_u64(&targets[0], 100);
        targets[1] = targets[0];
        targets[2] = targets[0];
        /* 窗口不足 N，必须拒绝 */
        CHECK(!dtc_lwma_next_target(&dtc_chain_main, times, 4, targets, 3, &out));
        /* 时间戳与目标数量不匹配，必须拒绝 */
        CHECK(!dtc_lwma_next_target(&dtc_chain_main, times, 3, targets, 3, &out));
    }
}
