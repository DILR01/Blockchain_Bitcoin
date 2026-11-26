/*
 * test_util.h —— 极简测试框架（单可执行文件聚合所有测试组）
 *
 * 设计取向：
 *   * 不引入第三方测试框架（保持零依赖、可离线构建）；
 *   * 每个断言失败都打印 文件:行号 与表达式，便于定位；
 *   * 全局统计 g_checks / g_failures，由 main 决定退出码。
 */
#ifndef DTC_TEST_UTIL_H
#define DTC_TEST_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* 全局计数（定义于 test_main.c） */
extern int g_checks;
extern int g_failures;

/* 断言实现：cond 为假时打印位置并累加失败数 */
void test_check_impl(bool cond, const char *expr, const char *file, int line);

/* 打印一条分组信息 */
void test_group(const char *name);

#define CHECK(cond) test_check_impl((cond), #cond, __FILE__, __LINE__)

/*
 * 把十六进制字符串解码到 out，返回字节数；失败返回 0 并记一次失败。
 * 测试输入用十六进制书写，便于与规范/向量逐字节对照。
 */
size_t check_hex(const char *hex, uint8_t *out, size_t cap);

/* 断言 data 的字节内容恰为 hex 描述 */
void check_bytes_hex(const uint8_t *data, size_t len, const char *hex);

/* ---- 各测试组（每个文件一个入口） ---- */
void test_crypto(void);
void test_uint256(void);
void test_reader(void);
void test_params(void);
void test_economics(void);
void test_lwma(void);
void test_pow(void);
void test_merkle(void);
void test_primitives(void);
void test_script(void);
void test_isolation(void);

#endif /* DTC_TEST_UTIL_H */
