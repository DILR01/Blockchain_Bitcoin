/*
 * dtc_interfaces.h —— 进程/模块解耦边界（node / wallet / gui 唯一通信面）
 *
 * 硬约束（来自 SPEC）：
 *   * node / wallet / gui 互不引用对方符号，只通过本文件的函数指针
 *     vtable 通信；
 *   * GUI 进程禁止链接 kernel；wallet 禁止依赖 kernel；
 *   * M8 落地为 dtc-node / dtc-wallet / dtc-gui 三进程，
 *     经 <datadir>/node.sock 的 UNIX socket 长度前缀帧 + handle 整数表通信。
 *
 * 当前 M1 阶段本文件只提供接口定义与常量，不提供实现；后续里程碑
 * 按同一 ABI 填充 dtc_node_api / dtc_wallet_api / dtc_gui_bridge。
 */
#ifndef DTC_INTERFACES_H
#define DTC_INTERFACES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 节点角色 */
typedef enum {
    DTC_ROLE_NODE = 0,
    DTC_ROLE_WALLET = 1,
    DTC_ROLE_GUI = 2
} dtc_role;

/* IPC 帧上限（避免恶意长度导致内存放大） */
#define DTC_IPC_MAX_FRAME (64u * 1024u * 1024u)
/* node.sock 相对 datadir 的文件名 */
#define DTC_IPC_SOCKET_NAME "node.sock"

/* 通知回调（来自 node 的异步事件）—— 任意线程触发、串行化 */
typedef struct {
    void *ctx;
    void (*block_tip)(void *ctx, const uint8_t hash[32], int32_t height);
    void (*header_tip)(void *ctx, const uint8_t hash[32], int32_t height);
    void (*progress)(void *ctx, int32_t verified, int32_t total);
    void (*warning_set)(void *ctx, const char *message);
    void (*warning_unset)(void *ctx, const char *message);
    void (*flush_error)(void *ctx, const char *message);
    void (*fatal_error)(void *ctx, const char *message);
} dtc_notifications;

/*
 * 节点控制面（供 wallet/gui 通过 IPC 代理）。
 * 返回缓冲区由调用方提供，避免跨进程所有权歧义。
 */
typedef struct {
    void *ctx;
    bool (*get_chain_info)(void *ctx, char *json, size_t cap, size_t *written);
    bool (*get_block_count)(void *ctx, int32_t *height);
    bool (*get_block_hash)(void *ctx, int32_t height, uint8_t out[32]);
    bool (*broadcast_tx)(void *ctx, const uint8_t *tx, size_t len,
                         char *err, size_t errcap);
    bool (*submit_block)(void *ctx, const uint8_t *blk, size_t len,
                         char *reason, size_t reasoncap);
} dtc_node_api;

/*
 * 钱包面（供 GUI 调用）。所有字符串均为 UTF-8。
 */
typedef struct {
    void *ctx;
    bool (*create_wallet)(void *ctx, const char *name, char *err, size_t errcap);
    bool (*get_new_address)(void *ctx, const char *label, char *addr_out,
                            size_t cap);
    bool (*get_balance)(void *ctx, int64_t *confirmed, int64_t *unconfirmed);
    bool (*send_to_address)(void *ctx, const char *address, int64_t amount,
                            char *txid_hex, size_t cap, char *err,
                            size_t errcap);
} dtc_wallet_api;

/*
 * GUI 桥：Qt 薄壳只允许包含本头文件。
 */
typedef struct {
    void *ctx;
    const dtc_node_api *node;
    const dtc_wallet_api *wallet;
    void (*request_shutdown)(void *ctx);
} dtc_gui_bridge;

#endif /* DTC_INTERFACES_H */
