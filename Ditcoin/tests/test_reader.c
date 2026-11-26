/*
 * test_reader.c —— CompactSize / 小端读写 / 可增长缓冲
 */
#include "test_util.h"

#include "dtc/reader.h"

void test_reader(void)
{
    test_group("varint 最小编码");
    {
        /* 1 字节：0x00..0xfc */
        uint8_t d1[] = {0xfc};
        dtc_reader r;
        dtc_reader_init(&r, d1, sizeof(d1));
        CHECK(dtc_read_varint(&r) == 0xfc);
        CHECK(dtc_reader_ok(&r));

        /* 3 字节：0xfd 0xfd 0x00 = 253 */
        uint8_t d3[] = {0xfd, 0xfd, 0x00};
        dtc_reader_init(&r, d3, sizeof(d3));
        CHECK(dtc_read_varint(&r) == 253);
        CHECK(dtc_reader_ok(&r));

        /* 5 字节 */
        uint8_t d5[] = {0xfe, 0x00, 0x00, 0x00, 0x01}; /* 2^24 */
        dtc_reader_init(&r, d5, sizeof(d5));
        CHECK(dtc_read_varint(&r) == 0x1000000ULL);
        CHECK(dtc_reader_ok(&r));

        /* 9 字节 */
        uint8_t d9[] = {0xff, 0, 0, 0, 0, 0, 0, 0, 1};
        dtc_reader_init(&r, d9, sizeof(d9));
        CHECK(dtc_read_varint(&r) == 0x0100000000000000ULL);
        CHECK(dtc_reader_ok(&r));
    }

    test_group("varint 非最小编码必须拒绝");
    {
        uint8_t bad1[] = {0xfd, 0x01, 0x00}; /* 1 应使用 1 字节编码 */
        uint8_t bad2[] = {0xfe, 0xff, 0xff, 0x00, 0x00};
        uint8_t bad3[] = {0xff, 0, 0, 0, 0, 0, 0, 0, 0};
        dtc_reader r;
        dtc_reader_init(&r, bad1, sizeof(bad1));
        (void)dtc_read_varint(&r);
        CHECK(!dtc_reader_ok(&r));
        dtc_reader_init(&r, bad2, sizeof(bad2));
        (void)dtc_read_varint(&r);
        CHECK(!dtc_reader_ok(&r));
        dtc_reader_init(&r, bad3, sizeof(bad3));
        (void)dtc_read_varint(&r);
        CHECK(!dtc_reader_ok(&r));
    }

    test_group("截断读取");
    {
        uint8_t d[] = {1, 2, 3};
        dtc_reader r;
        dtc_reader_init(&r, d, sizeof(d));
        CHECK(dtc_read_u8(&r) == 1);
        CHECK(dtc_read_u32(&r) == 0);
        CHECK(!dtc_reader_ok(&r));
        /* 出错后 pos 不再推进；剩余量按安全约定返回 0 */
        CHECK(dtc_reader_pos(&r) == 1);
        CHECK(dtc_reader_remaining(&r) == 0);
    }

    test_group("小端整数");
    {
        uint8_t d[] = {0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89};
        dtc_reader r;
        dtc_reader_init(&r, d, sizeof(d));
        CHECK(dtc_read_u32(&r) == 0x12345678u);
        CHECK(dtc_read_u32(&r) == 0x89abcdefu);
        CHECK(dtc_reader_ok(&r));
    }

    test_group("可增长缓冲");
    {
        dtc_buf b;
        dtc_buf_init(&b);
        CHECK(dtc_buf_u8(&b, 0x01));
        CHECK(dtc_buf_varint(&b, 300));
        CHECK(dtc_buf_u32(&b, 0xdeadbeefu));
        CHECK(dtc_buf_i64(&b, -2));
        CHECK(!b.err);
        CHECK(b.len == 1 + 3 + 4 + 8);

        dtc_reader r;
        dtc_reader_init(&r, b.data, b.len);
        CHECK(dtc_read_u8(&r) == 0x01);
        CHECK(dtc_read_varint(&r) == 300);
        CHECK(dtc_read_u32(&r) == 0xdeadbeefu);
        CHECK(dtc_read_i64(&r) == -2);
        CHECK(dtc_reader_ok(&r));
        CHECK(dtc_reader_remaining(&r) == 0);

        CHECK(dtc_varint_size(0) == 1);
        CHECK(dtc_varint_size(0xfc) == 1);
        CHECK(dtc_varint_size(0xfd) == 3);
        CHECK(dtc_varint_size(0xffff) == 3);
        CHECK(dtc_varint_size(0x10000) == 5);
        CHECK(dtc_varint_size(0x100000000ULL) == 9);
        dtc_buf_free(&b);
    }
}
