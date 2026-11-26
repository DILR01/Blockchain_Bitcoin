/*
 * test_economics.c —— 尾排放经济模型
 *
 * 覆盖：
 *   * 7 段补贴表逐段断言；
 *   * 前 2,520,000 块补贴之和 == PRE_TAIL_SUPPLY；
 *   * supply_at 闭式解与逐块累加一致；
 *   * 第 50/100/200/1000 年的供给量（与提示词中的实测值一致）。
 */
#include "test_util.h"

#include "dtc/amount.h"
#include "dtc/consensus.h"

void test_economics(void)
{
    test_group("补贴分段表");
    CHECK(dtc_subsidy(0) == 2500000000LL);
    CHECK(dtc_subsidy(419999) == 2500000000LL);
    CHECK(dtc_subsidy(420000) == 1250000000LL);
    CHECK(dtc_subsidy(839999) == 1250000000LL);
    CHECK(dtc_subsidy(840000) == 625000000LL);
    CHECK(dtc_subsidy(1259999) == 625000000LL);
    CHECK(dtc_subsidy(1260000) == 312500000LL);
    CHECK(dtc_subsidy(1679999) == 312500000LL);
    CHECK(dtc_subsidy(1680000) == 156250000LL);
    CHECK(dtc_subsidy(2099999) == 156250000LL);
    CHECK(dtc_subsidy(2100000) == 78125000LL);
    CHECK(dtc_subsidy(2519999) == 78125000LL);
    CHECK(dtc_subsidy(2520000) == 50000000LL);
    CHECK(dtc_subsidy(100000000) == 50000000LL); /* 尾排放永久 0.5 DTC */
    CHECK(dtc_subsidy(-1) == 0);

    test_group("分段函数");
    for (uint32_t seg = 0; seg < 6; ++seg) {
        int64_t expect = 2500000000LL >> seg;
        CHECK(dtc_subsidy_for_segment(seg) == expect);
    }
    CHECK(dtc_subsidy_for_segment(6) == 50000000LL);

    test_group("pre_tail_supply");
    CHECK(dtc_pre_tail_supply() == 2067187500000000LL);
    CHECK(dtc_chain_main.pre_tail_supply == dtc_pre_tail_supply());
    {
        /* 逐块累加前 2,520,000 块，必须与常量完全一致 */
        int64_t total = 0;
        for (int32_t h = 0; h < 2520000; ++h) {
            total += dtc_subsidy(h);
        }
        CHECK(total == 2067187500000000LL);
    }

    test_group("supply_at 闭式解");
    CHECK(dtc_supply_at(0) == 0);
    CHECK(dtc_supply_at(-5) == 0);
    CHECK(dtc_supply_at(1) == 2500000000LL);
    CHECK(dtc_supply_at(420000) == 420000LL * 2500000000LL);
    CHECK(dtc_supply_at(2520000) == 2067187500000000LL);
    CHECK(dtc_supply_at(2520001) == 2067187500000000LL + 50000000LL);
    CHECK(dtc_supply_at(2520010) == 2067187500000000LL + 10LL * 50000000LL);

    test_group("supply_at 与逐块累加一致（抽样）");
    {
        int64_t acc = 0;
        int64_t next_check = 0;
        for (int32_t h = 0; h < 3000000; ++h) {
            if (h == next_check) {
                CHECK(dtc_supply_at(h) == acc);
                next_check += 137137; /* 非对齐采样，覆盖段边界附近 */
            }
            acc += dtc_subsidy(h);
        }
    }

    test_group("年度供给指标");
    {
        int64_t y50 = 50LL * 52560;
        int64_t y100 = 100LL * 52560;
        int64_t y200 = 200LL * 52560;
        int64_t y1000 = 1000LL * 52560;
        CHECK(dtc_supply_at(y50) == 2072587500000000LL);
        CHECK(dtc_supply_at(y100) == 2203987500000000LL);
        CHECK(dtc_supply_at(y200) == 2466787500000000LL);
        CHECK(dtc_supply_at(y1000) == 4569187500000000LL);
        /* 单调递增，且无硬上限 */
        CHECK(dtc_supply_at(y1000 + 1) > dtc_supply_at(y1000));
        CHECK(dtc_subsidy(1000000000) == 50000000LL);
    }

    test_group("金额格式化");
    {
        char buf[32];
        int n = dtc_amount_format(2067187500000000LL, buf, sizeof(buf));
        CHECK(n > 0);
        CHECK(strcmp(buf, "20671875.00000000") == 0);
        CHECK(dtc_money(25) == 2500000000LL);
        int64_t sum = 0;
        CHECK(dtc_amount_add(2500000000LL, 50000000LL, &sum));
        CHECK(sum == 2550000000LL);
        CHECK(!dtc_amount_add(-1, 0, &sum));
    }
}
