/*
 * ecdsa.c —— libsecp256k1 胶水层
 *
 * 只做三件事：
 *   1. 维护一个 secp256k1_context（VERIFY 模式）；
 *   2. 严格解析公钥（33/65 字节）与 DER 签名，并强制 low-S；
 *   3. 把 32 字节摘要交给 secp256k1_ecdsa_verify。
 *
 * 任何解析失败都必须返回 false —— 脚本层据此判定签名无效，
 * 绝不允许「解析失败当成功」。
 */
#include "dtc/secp.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>

/* 内部上下文结构：包一层便于未来加入预计算表缓存 */
typedef struct {
    secp256k1_context *ctx;
} ecdsa_impl;

/*
 * 脚本引擎回调：签名校验。
 *   sig/siglen     —— 已去掉末尾 hashtype 字节的 DER 签名
 *   pubkey/pklen   —— SEC 编码公钥
 *   sighash        —— 32 字节摘要
 */
static bool check_ecdsa(void *ctx, const uint8_t *sig, size_t siglen,
                        const uint8_t *pubkey, size_t pubkeylen,
                        const uint8_t sighash[32])
{
    ecdsa_impl *impl = (ecdsa_impl *)ctx;
    if (impl == NULL || impl->ctx == NULL || sighash == NULL) {
        return false;
    }
    /* 公钥长度白名单：压缩 33 / 非压缩 65 */
    if (pubkey == NULL || (pubkeylen != 33 && pubkeylen != 65)) {
        return false;
    }
    if (sig == NULL || siglen == 0) {
        return false;
    }

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(impl->ctx, &pk, pubkey, pubkeylen) != 1) {
        return false;
    }

    secp256k1_ecdsa_signature parsed;
    /* parse_der 内部强制 BIP66 严格 DER，不合法直接返回 0 */
    if (secp256k1_ecdsa_signature_parse_der(impl->ctx, &parsed, sig, siglen) !=
        1) {
        return false;
    }

    /* low-S 检查：归一化后与原签名不同，说明原签名是高 S，直接拒绝 */
    secp256k1_ecdsa_signature normalized;
    if (secp256k1_ecdsa_signature_normalize(impl->ctx, &normalized, &parsed) ==
        1) {
        return false;
    }

    return secp256k1_ecdsa_verify(impl->ctx, &parsed, sighash, &pk) == 1;
}

bool dtc_ecdsa_checker_init(dtc_ecdsa_checker *checker)
{
    if (checker == NULL) {
        return false;
    }
    memset(checker, 0, sizeof(*checker));

    ecdsa_impl *impl = (ecdsa_impl *)calloc(1, sizeof(ecdsa_impl));
    if (impl == NULL) {
        return false;
    }
    impl->ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (impl->ctx == NULL) {
        free(impl);
        return false;
    }

    checker->impl = impl;
    checker->iface.ctx = impl;
    checker->iface.check_ecdsa = check_ecdsa;
    return true;
}

void dtc_ecdsa_checker_destroy(dtc_ecdsa_checker *checker)
{
    if (checker == NULL || checker->impl == NULL) {
        return;
    }
    ecdsa_impl *impl = (ecdsa_impl *)checker->impl;
    if (impl->ctx != NULL) {
        secp256k1_context_destroy(impl->ctx);
    }
    free(impl);
    checker->impl = NULL;
    memset(&checker->iface, 0, sizeof(checker->iface));
}
