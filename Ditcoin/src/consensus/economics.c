/*
 * economics.c —— 尾排放经济模型
 *
 * ★ 这是与 Bitcoin 的本质差异，不是等价参数变换：
 *   * 无 2100 万硬上限；
 *   * 6 次减半后进入永久 0.5 DTC/块的尾排放；
 *   * 货币总量由 supply_at(h) 单调函数描述，替代 MAX_MONEY 共识上界。
 *
 * 所有数值从 dtc_chain_main 读取，本文件不出现裸魔数。
 */
#include "dtc/consensus.h"

#include <stdint.h>

/* 取当前经济模型参数（三条网络一致） */
static const dtc_chain_params *econ_params(void)
{
    return &dtc_chain_main;
}

int64_t dtc_subsidy(int32_t height)
{
    if (height < 0) {
        return 0;
    }

    const dtc_chain_params *p = econ_params();
    int64_t interval = p->halving_interval;
    uint32_t stage = (uint32_t)((int64_t)height / interval);

    /* h >= 63 时右移在 C 语言中属于未定义行为，显式截断为 0；
     * 之后仍会被尾排放下限兜底，因此最终结果恒为 0.5 DTC。 */
    int64_t s = (stage >= 63u) ? 0 : (p->initial_subsidy >> stage);
    return (s > p->tail_floor) ? s : p->tail_floor;
}

int64_t dtc_supply_at(int64_t height)
{
    if (height <= 0) {
        return 0;
    }

    const dtc_chain_params *p = econ_params();
    if (height <= p->tail_start_height) {
        int64_t total = 0;
        int64_t s = p->initial_subsidy;
        int64_t rem = height;
        while (rem > 0) {
            int64_t take = (rem < p->halving_interval) ? rem
                                                       : p->halving_interval;
            total += s * take;
            rem -= take;
            s >>= 1;
            if (s < p->tail_floor) {
                s = p->tail_floor;
            }
        }
        return total;
    }

    /* 闭式解：前 252 万块固定，之后线性增长。
     * 防御性溢出检查（高度达到 1e15 量级才会触发，远超实际使用）。 */
    int64_t extra_blocks = height - p->tail_start_height;
    if (extra_blocks > (INT64_MAX - p->pre_tail_supply) / p->tail_floor) {
        return INT64_MAX;
    }
    return p->pre_tail_supply + extra_blocks * p->tail_floor;
}

int64_t dtc_subsidy_for_segment(uint32_t segment)
{
    const dtc_chain_params *p = econ_params();
    if (segment >= p->halving_count) {
        /* 第 6 段起：尾排放 */
        return p->tail_floor;
    }
    int64_t s = p->initial_subsidy >> segment;
    return (s > p->tail_floor) ? s : p->tail_floor;
}

int64_t dtc_pre_tail_supply(void)
{
    return econ_params()->pre_tail_supply;
}
