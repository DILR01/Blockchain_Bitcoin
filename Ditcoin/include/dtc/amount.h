/*
 * amount.h —— Ditcoin 金额类型（单位：ditoshi，1 DTC = 100,000,000 dts）
 *
 * ★ 与 Bitcoin 的关键差异：
 *   不存在 MAX_MONEY 这一「共识上界」常量。货币上界由 dtc_supply_at(h)
 *   这一单调增函数决定（见 economics.h），任何时刻的 UTXO 总额都必须
 *   满足 total_out ≤ dtc_supply_at(height+1)。
 */
#ifndef DTC_AMOUNT_H
#define DTC_AMOUNT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 金额使用有符号 64 位，便于在验证路径上做减法与溢出检测 */
typedef int64_t dtc_amount;

/* 1 DTC 对应的 dts 数（10^8） */
#define DTC_COIN 100000000LL
/* 金额绝对值上限（防止 int64 溢出），不是货币发行上界：约 92 亿 DTC */
#define DTC_AMOUNT_ABS_MAX (INT64_MAX / 2)

/* 构造 DTC 金额：dtc_money(25) == 25 DTC == 2,500,000,000 dts */
dtc_amount dtc_money(int64_t whole_dtc);

/* 金额是否在 int64 安全范围内（不含供应量语义） */
bool dtc_amount_is_representable(dtc_amount v);

/*
 * 金额加法：任一操作数为负、或和溢出范围时返回 false。
 * 共识路径上金额永远非负。
 */
bool dtc_amount_add(dtc_amount a, dtc_amount b, dtc_amount *out);

/* 金额是否落在[0, DTC_AMOUNT_ABS_MAX]内 */
bool dtc_amount_in_range(dtc_amount v);

/*
 * 将金额格式化为 "%lld.%08lld" 形式的字符串（例如 20671875.00000000）。
 * buf 建议不小于 32 字节；返回写入的字符数（不含 '\0'）。
 */
int dtc_amount_format(dtc_amount v, char *buf, size_t buflen);

#endif /* DTC_AMOUNT_H */
