/*
 * amount.c —— 金额工具
 */
#include "dtc/amount.h"

#include <stdio.h>

dtc_amount dtc_money(int64_t whole_dtc)
{
    return whole_dtc * DTC_COIN;
}

bool dtc_amount_is_representable(dtc_amount v)
{
    /* 排除 INT64_MIN 取反溢出的情况 */
    return v > -DTC_AMOUNT_ABS_MAX && v < DTC_AMOUNT_ABS_MAX;
}

bool dtc_amount_add(dtc_amount a, dtc_amount b, dtc_amount *out)
{
    if (a < 0 || b < 0) {
        return false;
    }
    if (a > DTC_AMOUNT_ABS_MAX - b) {
        return false;
    }
    *out = a + b;
    return true;
}

bool dtc_amount_in_range(dtc_amount v)
{
    return v >= 0 && v <= DTC_AMOUNT_ABS_MAX;
}

int dtc_amount_format(dtc_amount v, char *buf, size_t buflen)
{
    if (buf == NULL || buflen == 0) {
        return -1;
    }
    bool neg = v < 0;
    /* 先取绝对值（v 不会等于 INT64_MIN，调用方保证金额范围） */
    uint64_t abs_v = (uint64_t)(neg ? -v : v);
    uint64_t whole = abs_v / (uint64_t)DTC_COIN;
    uint64_t frac = abs_v % (uint64_t)DTC_COIN;
    int n = snprintf(buf, buflen, "%s%llu.%08llu", neg ? "-" : "",
                     (unsigned long long)whole, (unsigned long long)frac);
    if (n < 0) {
        return -1;
    }
    return n;
}
