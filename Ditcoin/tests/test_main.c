/*
 * test_main.c —— 测试入口
 *
 * 依次运行 M0（密码学/工具）与 M1（共识/原语/脚本/隔离）测试组。
 * 任一断言失败，进程退出码为 1，便于 CI 与 ctest 判定。
 */
#include "test_util.h"

#include "dtc/hex.h"

int g_checks = 0;
int g_failures = 0;

void test_check_impl(bool cond, const char *expr, const char *file, int line)
{
    ++g_checks;
    if (!cond) {
        ++g_failures;
        printf("FAIL %s:%d  %s\n", file, line, expr);
    }
}

void test_group(const char *name)
{
    printf("[group] %s\n", name);
}

size_t check_hex(const char *hex, uint8_t *out, size_t cap)
{
    size_t len = strlen(hex);
    int n = dtc_hex_decode(hex, len, out, cap);
    if (n < 0) {
        ++g_checks;
        ++g_failures;
        printf("FAIL 十六进制解码失败: %s\n", hex);
        return 0;
    }
    return (size_t)n;
}

void check_bytes_hex(const uint8_t *data, size_t len, const char *hex)
{
    uint8_t want[256];
    size_t n = check_hex(hex, want, sizeof(want));
    CHECK(n == len);
    if (n == len && len > 0) {
        CHECK(memcmp(data, want, len) == 0);
    }
}

int main(void)
{
    printf("=== Ditcoin 测试套件 ===\n");

    test_crypto();
    test_uint256();
    test_reader();
    test_params();
    test_economics();
    test_lwma();
    test_pow();
    test_merkle();
    test_primitives();
    test_script();
    test_isolation();

    printf("=== 完成：%d 项断言，%d 项失败 ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
