/*
 * zxsec-record.c - openconnect 批量记录层实现
 *
 * 底层：/dev/zx279133-sec SUBMIT_BATCH ioctl（≤16 条/次）+ arena mmap。
 * 槽位布局（与 zxsec-gnutls-backend.c / mihomo 反汇编一致）：
 *   [0..127]  AAD
 *   [128..]   数据（加密时明文/解密时密文）
 *   硬件在 [128+data_len] 处追加/读取 16B tag
 *
 * 解密约定（设备实测，zxsec-gnutls-backend.c 同款）：
 *   data_len = 密文长度；tag 紧跟其后放在槽内；result 负值 = 失败（含 tag 错）；
 *   成功时 result 不可靠，输出长度恒 = data_len（GCM ct/pt 等长）。
 */
#define _GNU_SOURCE
#include "zxsec-record.h"
#include "zxsec_uapi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define ZXREC_AAD_OFF    128

/* 诊断：ZXREC_DBG=1 时打印每个失败分支（selftest/现场排障用） */
#include <stdio.h>
#define ZXDBG(...)  do { if (zxdbg()) fprintf(stderr, "[zxdbg] " __VA_ARGS__); } while (0)
static int zxdbg(void)
{
    static int v = -1;
    if (v < 0)
        v = getenv("ZXREC_DBG") ? 1 : 0;
    return v;
}
#define ZXREC_MAX_AAD    128

/* TLS/DTLS 版本字节 */
#define VER_TLS12_HI  0x03
#define VER_TLS12_LO  0x03
#define VER_DTLS12_HI 0xFE
#define VER_DTLS12_LO 0xFD

#define REC_APPDATA 0x17

struct zxrec_dir {
    uint32_t sess_id;            /* 驱动句柄，0 也是合法值 */
    int      have_key;           /* 密钥是否已安装（不能拿 sess_id!=0 判断） */
    uint8_t  salt[ZXREC_SALT_LEN];
    uint16_t epoch;              /* DTLS TX 用 */
    uint64_t seq;                /* TLS: 64b 计数器; DTLS TX: 48b 计数器 */
    int      alg_bit;
    int      keylen;
    uint8_t  key[32];
};

struct zxsec_rl {
    int      fd;
    uint8_t *arena;
    uint32_t arena_size, slot_size, nslots, max_batch;
    size_t   max_data;
    struct zxrec_dir r, w;
    int      is_dtls;
    /* 统计 */
    unsigned long seal_ops, open_ops, batches;
};

/* ---------------- 设备与槽位 ---------------- */

int zxsec_rl_init(struct zxsec_rl **out)
{
    struct zxsec_rl *rl;
    struct zxsec_info info;
    struct zxsec_set_arena sa;

    rl = calloc(1, sizeof(*rl));
    if (!rl)
        return -ENOMEM;

    rl->fd = open(ZXSEC_DEV_SEC, O_RDWR | O_CLOEXEC);
    if (rl->fd < 0) {
        int e = -errno;
        free(rl);
        return e;
    }

    memset(&info, 0, sizeof(info));
    if (ioctl(rl->fd, ZXSEC_IOC_INFO, &info) < 0 || info.abi_version != 1) {
        close(rl->fd);
        free(rl);
        return -EIO;
    }

    rl->arena_size = info.arena_size ? info.arena_size : (2u << 20);
    rl->slot_size  = info.slot_size  ? info.slot_size  : (64u << 10);
    rl->max_batch  = info.max_batch  ? info.max_batch  : ZXREC_MAX_BATCH;
    if (rl->max_batch > ZXREC_MAX_BATCH)
        rl->max_batch = ZXREC_MAX_BATCH;
    rl->nslots   = rl->arena_size / rl->slot_size;
    rl->max_data = rl->slot_size - ZXREC_AAD_OFF - ZXREC_TAG_LEN;

    memset(&sa, 0, sizeof(sa));
    sa.arena_bytes = rl->arena_size;
    if (ioctl(rl->fd, ZXSEC_IOC_SET_ARENA, &sa) < 0)
        ZXDBG("SET_ARENA failed: errno=%d (%s)\n", errno, strerror(errno));
    ZXDBG("init: arena_size=%u slot_size=%u max_batch=%u nslots=%u max_data=%zu\n",
          rl->arena_size, rl->slot_size, rl->max_batch, rl->nslots, rl->max_data);

    rl->arena = mmap(NULL, rl->arena_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, rl->fd, 0);
    if (rl->arena == MAP_FAILED) {
        close(rl->fd);
        free(rl);
        return -EIO;
    }

    *out = rl;
    return 0;
}

void zxsec_rl_close(struct zxsec_rl *rl)
{
    if (!rl)
        return;
    if (rl->r.have_key)
        ioctl(rl->fd, ZXSEC_IOC_FREE_SESS, &rl->r.sess_id);
    if (rl->w.have_key)
        ioctl(rl->fd, ZXSEC_IOC_FREE_SESS, &rl->w.sess_id);
    if (rl->arena)
        munmap(rl->arena, rl->arena_size);
    close(rl->fd);
    free(rl);
}

void zxsec_rl_stats(struct zxsec_rl *rl, unsigned long *seal_ops,
                    unsigned long *open_ops, unsigned long *batches)
{
    if (seal_ops) *seal_ops = rl->seal_ops;
    if (open_ops) *open_ops = rl->open_ops;
    if (batches)  *batches  = rl->batches;
}

/* ---------------- 密钥 ---------------- */

static int rl_alloc_sess(struct zxsec_rl *rl, struct zxrec_dir *d)
{
    struct zxsec_alloc_sess as;
    uint32_t old = d->sess_id;

    memset(&as, 0, sizeof(as));
    as.alg_bit = (d->keylen == 16) ? ZXSEC_ALG_AES128_GCM_BIT
                                   : ZXSEC_ALG_AES256_GCM_BIT;
    as.key_len = (uint32_t)d->keylen;
    memcpy(as.key, d->key, d->keylen);
    if (ioctl(rl->fd, ZXSEC_IOC_ALLOC_SESS, &as) < 0) {
        ZXDBG("ALLOC_SESS failed: errno=%d (%s)\n", errno, strerror(errno));
        return -EIO;
    }
    d->sess_id = as.sess_id;
    ZXDBG("alloc dir sess_id=%u alg=%u key_len=%u\n",
          as.sess_id, as.alg_bit, as.key_len);
    /* 换密钥时释放旧会话：sess_id=0 也是合法句柄，用 have_key 判断 */
    if (d->have_key)
        ioctl(rl->fd, ZXSEC_IOC_FREE_SESS, &old);
    return 0;
}

int zxsec_rl_set_key(struct zxsec_rl *rl, int dir,
                     const uint8_t *key, int keylen,
                     const uint8_t *salt, uint16_t epoch, int is_dtls)
{
    struct zxrec_dir *d = dir ? &rl->w : &rl->r;

    if (keylen != 16 && keylen != 32)
        return -EINVAL;
    rl->is_dtls = is_dtls;
    d->keylen  = keylen;
    d->alg_bit = (keylen == 16) ? ZXSEC_ALG_AES128_GCM_BIT
                                : ZXSEC_ALG_AES256_GCM_BIT;
    memcpy(d->key, key, keylen);
    memcpy(d->salt, salt, ZXREC_SALT_LEN);
    d->epoch = epoch;
    /* 新密钥 = 新序号空间。写方向两种传输都必须从 1 起：
     * libssl 已经用新密钥、seq 0 发过 Finished，若自管记录层也从 0 开始，
     * DTLS 服务端的重放窗口会把记录当重复包丢弃；TLS 服务端则会因为
     * nonce/AAD 里的 seq 不对而直接解密失败（表现为隧道内 0 回包）。
     * 读方向：DTLS 的 seq 在报文头里，TLS 从记录体内的显式 nonce 取，
     * 都不依赖这个计数器。 */
    d->seq = dir ? 1 : 0;
    if (rl_alloc_sess(rl, d))
        return -EIO;
    d->have_key = 1;
    return 0;
}

void zxsec_rl_set_seq(struct zxsec_rl *rl, int dir, uint64_t seq)
{
    if (!rl)
        return;
    (dir ? &rl->w : &rl->r)->seq = seq;
}

/* ---------------- nonce / aad / 记录头 ---------------- */

static void build_nonce(const struct zxrec_dir *d, uint8_t *nonce12,
                        uint64_t seq8)
{
    memcpy(nonce12, d->salt, ZXREC_SALT_LEN);
    for (int i = 0; i < 8; i++)
        nonce12[ZXREC_SALT_LEN + i] = (uint8_t)(seq8 >> (56 - 8 * i));
}

/* seq8: TLS = 内部计数器；DTLS = epoch<<48 | seq48 */
static void build_aad(uint8_t aad[ZXREC_AAD_LEN], uint64_t seq8,
                      size_t ct_len, int is_dtls)
{
    for (int i = 0; i < 8; i++)
        aad[i] = (uint8_t)(seq8 >> (56 - 8 * i));
    aad[8]  = REC_APPDATA;
    aad[9]  = is_dtls ? VER_DTLS12_HI : VER_TLS12_HI;
    aad[10] = is_dtls ? VER_DTLS12_LO : VER_TLS12_LO;
    aad[11] = (uint8_t)(ct_len >> 8);
    aad[12] = (uint8_t)(ct_len & 0xff);
}

/* ---------------- 批量提交核心 ---------------- */

/* ZXREC_SUBMIT_ONE=1：逐条 SUBMIT_ONE（排障用，验证 BATCH 解密路径问题） */
static int zx_one_mode(void)
{
    static int v = -1;
    if (v < 0)
        v = getenv("ZXREC_SUBMIT_ONE") ? 1 : 0;
    return v;
}

static int rl_submit(struct zxsec_rl *rl, struct zxsec_op_request *reqs,
                     int n)
{
    struct zxsec_submit_batch sb;
    int i, bad = 0;

    if (zx_one_mode()) {
        for (i = 0; i < n; i++) {
            if (ioctl(rl->fd, ZXSEC_IOC_SUBMIT_ONE, &reqs[i]) < 0) {
                ZXDBG("SUBMIT_ONE ioctl failed: errno=%d (%s)\n",
                      errno, strerror(errno));
                reqs[i].result = -EIO;
                bad = 1;
            } else if (reqs[i].result < 0) {
                ZXDBG("SUBMIT_ONE op %d rejected: result=%d\n",
                      i, reqs[i].result);
                bad = 1;
            }
        }
        rl->batches++;
        return bad ? -EBADMSG : 0;
    }

    memset(&sb, 0, sizeof(sb));
    sb.reqs_ptr = (uint64_t)(uintptr_t)reqs;
    sb.count    = (uint32_t)n;
    if (ioctl(rl->fd, ZXSEC_IOC_SUBMIT_BATCH, &sb) < 0) {
        ZXDBG("SUBMIT_BATCH ioctl failed: errno=%d (%s) count=%u\n",
              errno, strerror(errno), sb.count);
        return -EIO;
    }
    ZXDBG("SUBMIT_BATCH done: sb.result=%d\n", sb.result);
    /* sb.result 非 0 表示有失败项，逐项检查 reqs[i].result */
    for (i = 0; i < n; i++)
        if (reqs[i].result < 0) {
            ZXDBG("BATCH op %d rejected: result=%d (len=%u)\n",
                  i, reqs[i].result, reqs[i].data_len);
            bad = 1;
        }
    rl->batches++;
    return bad ? -EBADMSG : 0;
}

static void rl_fill_req(struct zxsec_op_request *r, uint32_t sess,
                        uint32_t slot_base, size_t data_len,
                        const uint8_t *nonce12, size_t aad_len, int is_dec)
{
    static int w4b0 = -1;

    memset(r, 0, ZXSEC_REQ_SIZE);
    r->sess_id  = sess;
    if (w4b0 < 0) {
        const char *e = getenv("ZXREC_W4B0");
        w4b0 = e ? (int)strtol(e, NULL, 0) : 1;
    }
    /*
     * 实测（设备 2026-11-26）：word4 字节 0 是方向位——
     *   0 = 加密（GHASH 对 CTR 输出=密文，标准 GCM）
     *   1 = 解密+硬件 tag 校验（tag 不匹配时 result=-EBADMSG）
     * 默认解密方向置 1，硬件自己验 tag；ZXREC_W4B0=0 可回退到
     * "输出 GHASH"旧行为（软件校验 tag）。
     */
    ((uint8_t *)&r->word4)[0] = (uint8_t)(is_dec ? w4b0 : 0);
    ((uint8_t *)&r->word4)[1] = ZXREC_TAG_LEN;
    *(uint16_t *)((uint8_t *)&r->word4 + 2) = (uint16_t)aad_len;
    r->arena_off = slot_base + ZXREC_AAD_OFF;
    r->slot_off  = slot_base;
    r->data_len  = (uint32_t)data_len;
    memcpy(r->nonce, nonce12, ZXREC_NONCE_LEN);
}

/* ---------------- 加密（TX） ---------------- */

int zxsec_rl_seal(struct zxsec_rl *rl, int is_dtls,
                  const struct iovec *in, int n,
                  uint8_t *out, size_t outcap, size_t *outlen,
                  struct iovec *dgram_out, int max_dgrams, int *n_dgrams)
{
    struct zxrec_dir *d = &rl->w;
    struct zxsec_op_request reqs[ZXREC_MAX_BATCH];
    uint64_t seq8[ZXREC_MAX_BATCH];
    uint32_t slot_base[ZXREC_MAX_BATCH];
    size_t ct_len[ZXREC_MAX_BATCH];
    uint8_t *cursor = out;
    int ret;

    if (!d->have_key) {
        ZXDBG("seal: no key installed (set_key w missed?)\n");
        return -EINVAL;
    }
    if (n < 1 || n > (int)rl->max_batch) {
        ZXDBG("seal: bad n=%d max_batch=%u\n", n, rl->max_batch);
        return -EINVAL;
    }

    for (int i = 0; i < n; i++) {
        if (in[i].iov_len == 0 || in[i].iov_len > rl->max_data) {
            ZXDBG("seal: bad iov_len=%zu (max_data=%zu)\n",
                  in[i].iov_len, rl->max_data);
            return -EINVAL;
        }
        seq8[i] = is_dtls ? (((uint64_t)d->epoch << 48) | (d->seq & 0xffffffffffffULL))
                          : d->seq;
        slot_base[i] = (uint32_t)i * rl->slot_size;
        ct_len[i] = in[i].iov_len;

        uint8_t *slot = rl->arena + slot_base[i];
        build_aad(slot, seq8[i], ct_len[i], is_dtls);
        memcpy(slot + ZXREC_AAD_OFF, in[i].iov_base, in[i].iov_len);

        uint8_t nonce12[ZXREC_NONCE_LEN];
        build_nonce(d, nonce12, seq8[i]);
        rl_fill_req(&reqs[i], d->sess_id, slot_base[i], ct_len[i],
                    nonce12, ZXREC_AAD_LEN, 0);
        d->seq++;                       /* TLS 计数器跨记录递增 */
    }

    ret = rl_submit(rl, reqs, n);
    if (ret)
        return ret;
    rl->seal_ops += (unsigned long)n;

    for (int i = 0; i < n; i++) {
        size_t rec_payload = ct_len[i] + ZXREC_EXPLICIT_IV_LEN + ZXREC_TAG_LEN;
        size_t rec_total = (is_dtls ? ZXREC_DTLS_HDR_LEN : ZXREC_TLS_HDR_LEN)
                           + rec_payload;

        if ((size_t)(cursor - out) + rec_total > outcap)
            return -ENOBUFS;

        if (is_dtls) {
            uint8_t *h = cursor;
            uint64_t s = seq8[i] & 0xffffffffffffULL;   /* 48 位 seq */
            h[0] = REC_APPDATA;
            h[1] = VER_DTLS12_HI;
            h[2] = VER_DTLS12_LO;
            h[3] = (uint8_t)(d->epoch >> 8);
            h[4] = (uint8_t)(d->epoch & 0xff);
            h[5] = (uint8_t)(s >> 40);
            h[6] = (uint8_t)(s >> 32);
            h[7] = (uint8_t)(s >> 24);
            h[8] = (uint8_t)(s >> 16);
            h[9] = (uint8_t)(s >> 8);
            h[10] = (uint8_t)s;
            h[11] = (uint8_t)(rec_payload >> 8);
            h[12] = (uint8_t)(rec_payload & 0xff);
        } else {
            cursor[0] = REC_APPDATA;
            cursor[1] = VER_TLS12_HI;
            cursor[2] = VER_TLS12_LO;
            cursor[3] = (uint8_t)(rec_payload >> 8);
            cursor[4] = (uint8_t)(rec_payload & 0xff);
        }
        {
            uint8_t *dst = cursor + (is_dtls ? ZXREC_DTLS_HDR_LEN
                                             : ZXREC_TLS_HDR_LEN);
            uint8_t *slot = rl->arena + slot_base[i];
            uint64_t sn = seq8[i];
            /* 记录体 = 显式 nonce(8) || 密文 || tag。显式部分就是 seq
             * （DTLS 为 epoch||seq48），必须与实际加密用的 nonce 一致，
             * 对端靠它重建 12 字节 nonce。漏写会让对端把密文前 8 字节
             * 当成 nonce，整条记录解密失败。 */
            for (int k = 0; k < ZXREC_EXPLICIT_IV_LEN; k++)
                dst[k] = (uint8_t)(sn >> (56 - 8 * k));
            memcpy(dst + ZXREC_EXPLICIT_IV_LEN, slot + ZXREC_AAD_OFF,
                   ct_len[i] + ZXREC_TAG_LEN);
        }
        if (dgram_out && i < max_dgrams) {
            dgram_out[i].iov_base = cursor;
            dgram_out[i].iov_len  = rec_total;
        }
        cursor += rec_total;
    }

    if (n_dgrams)
        *n_dgrams = is_dtls ? n : 0;
    *outlen = (size_t)(cursor - out);
    return 0;
}

/* ---------------- 解密（RX） ---------------- */

/* 软件 tag 校验开关：默认开。ZXREC_SW_TAG=0 关闭（硬件行为调查用）。
 * 每次读 env（不缓存），selftest 可运行中切换。 */
static int zx_sw_tag(void)
{
    const char *e = getenv("ZXREC_SW_TAG");
    return !(e && !strcmp(e, "0"));
}

int zxsec_rl_open_dtls(struct zxsec_rl *rl,
                       const struct iovec *in, int n,
                       struct iovec *out, int *out_lens, uint8_t *types)
{
    struct zxrec_dir *d = &rl->r;
    struct zxsec_op_request reqs[ZXREC_MAX_BATCH];
    uint32_t slot_base[ZXREC_MAX_BATCH];
    size_t ct_len[ZXREC_MAX_BATCH];
    uint64_t seq8[ZXREC_MAX_BATCH];

    if (!d->have_key)
        return -EINVAL;
    if (n < 1 || n > (int)rl->max_batch)
        return -EINVAL;

    for (int i = 0; i < n; i++) {
        const uint8_t *p = in[i].iov_base;
        size_t len = in[i].iov_len;
        uint16_t epoch;
        uint64_t seq48;

        if (len < ZXREC_DTLS_HDR_LEN + ZXREC_TAG_LEN || p[0] != REC_APPDATA) {
            ZXDBG("open_dtls[%d]: bad head type=%02x len=%zu\n", i, p[0], len);
            return -EBADMSG;
        }
        epoch = ((uint16_t)p[3] << 8) | p[4];
        seq48 = ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 32) |
                ((uint64_t)p[7] << 24) | ((uint64_t)p[8] << 16) |
                ((uint64_t)p[9] << 8) | p[10];
        /* 头部 payload = 显式 nonce + 密文 + tag */
        {
            size_t body = ((size_t)p[11] << 8) | p[12];
            if (body < ZXREC_EXPLICIT_IV_LEN + ZXREC_TAG_LEN) {
                ZXDBG("open_dtls[%d]: short body %zu\n", i, body);
                return -EBADMSG;
            }
            ct_len[i] = body - ZXREC_EXPLICIT_IV_LEN - ZXREC_TAG_LEN;
        }
        if (len != ZXREC_DTLS_HDR_LEN + ZXREC_EXPLICIT_IV_LEN
                   + ct_len[i] + ZXREC_TAG_LEN) {
            ZXDBG("open_dtls[%d]: len mismatch ct=%zu rec=%zu\n",
                  i, ct_len[i], len - ZXREC_DTLS_HDR_LEN);
            return -EBADMSG;
        }
        if (ct_len[i] > rl->max_data) {
            ZXDBG("open_dtls[%d]: ct too big %zu\n", i, ct_len[i]);
            return -EINVAL;
        }

        seq8[i] = ((uint64_t)epoch << 48) | seq48;
        slot_base[i] = (uint32_t)i * rl->slot_size;
        uint8_t *slot = rl->arena + slot_base[i];
        build_aad(slot, seq8[i], ct_len[i], 1);
        /* 密文 + tag 一起拷入（跳过 8 字节显式 nonce） */
        memcpy(slot + ZXREC_AAD_OFF,
               p + ZXREC_DTLS_HDR_LEN + ZXREC_EXPLICIT_IV_LEN,
               ct_len[i] + ZXREC_TAG_LEN);

        uint8_t nonce12[ZXREC_NONCE_LEN];
        build_nonce(d, nonce12, seq8[i]);
        rl_fill_req(&reqs[i], d->sess_id, slot_base[i], ct_len[i],
                    nonce12, ZXREC_AAD_LEN, 1);
    }

    int ret = rl_submit(rl, reqs, n);
    if (ret)
        return ret;
    rl->open_ops += (unsigned long)n;

    /*
     * 实测（设备 2026-11-26）：硬件解密不校验 tag，而是把重算的 GCM tag
     * 写回槽内 arena_off+data_len 处 —— tag 校验在软件做（16B memcmp，
     * 开销可忽略）。任一记录不匹配返回 -EBADMSG。
     * ZXREC_SW_TAG=0 可关闭软件校验（硬件行为调查用）。
     */
    if (zx_sw_tag()) {
        for (int i = 0; i < n; i++) {
            const uint8_t *wire_tag = (const uint8_t *)in[i].iov_base
                                      + ZXREC_DTLS_HDR_LEN
                                      + ZXREC_EXPLICIT_IV_LEN + ct_len[i];
            const uint8_t *hw_tag = rl->arena + slot_base[i] + ZXREC_AAD_OFF + ct_len[i];
            if (memcmp(hw_tag, wire_tag, ZXREC_TAG_LEN) != 0) {
                ZXDBG("open_dtls[%d]: tag mismatch (seq %llu)\n",
                      i, (unsigned long long)seq8[i]);
                return -EBADMSG;
            }
        }
    }
    for (int i = 0; i < n; i++) {
        out[i].iov_base = rl->arena + slot_base[i] + ZXREC_AAD_OFF;
        out_lens[i] = (int)ct_len[i];
        types[i] = REC_APPDATA;
    }
    return 0;
}

int zxsec_rl_open_tls(struct zxsec_rl *rl,
                      const struct iovec *in, int n,
                      struct iovec *out, int *out_lens)
{
    struct zxrec_dir *d = &rl->r;
    struct zxsec_op_request reqs[ZXREC_MAX_BATCH];
    uint32_t slot_base[ZXREC_MAX_BATCH];
    size_t ct_len[ZXREC_MAX_BATCH];
    uint64_t seq8[ZXREC_MAX_BATCH];

    if (!d->have_key)
        return -EINVAL;
    if (n < 1 || n > (int)rl->max_batch)
        return -EINVAL;

    for (int i = 0; i < n; i++) {
        const uint8_t *p = in[i].iov_base;
        size_t len = in[i].iov_len;

        if (len < ZXREC_TLS_HDR_LEN + ZXREC_TAG_LEN || p[0] != REC_APPDATA) {
            ZXDBG("open_tls[%d]: bad head type=%02x len=%zu\n", i, p[0], len);
            return -EBADMSG;
        }
        /* 头部 payload = 显式 nonce + 密文 + tag（GCM：密文长 = 明文长） */
        {
            size_t body = ((size_t)p[3] << 8) | p[4];
            if (body < ZXREC_EXPLICIT_IV_LEN + ZXREC_TAG_LEN) {
                ZXDBG("open_tls[%d]: short body %zu\n", i, body);
                return -EBADMSG;
            }
            ct_len[i] = body - ZXREC_EXPLICIT_IV_LEN - ZXREC_TAG_LEN;
        }
        if (len != ZXREC_TLS_HDR_LEN + ZXREC_EXPLICIT_IV_LEN
                   + ct_len[i] + ZXREC_TAG_LEN) {
            ZXDBG("open_tls[%d]: len mismatch ct=%zu rec=%zu\n",
                  i, ct_len[i], len - ZXREC_TLS_HDR_LEN);
            return -EBADMSG;
        }
        if ((ssize_t)ct_len[i] < 0) {
            ZXDBG("open_tls[%d]: payload < tag\n", i);
            return -EBADMSG;
        }
        if (ct_len[i] > rl->max_data) {
            ZXDBG("open_tls[%d]: ct too big %zu\n", i, ct_len[i]);
            return -EINVAL;
        }

        /* 显式 nonce 就是 seq，直接以记录内的为准，避免计数器漂移 */
        {
            uint64_t s = 0;
            for (int k = 0; k < ZXREC_EXPLICIT_IV_LEN; k++)
                s = (s << 8) | p[ZXREC_TLS_HDR_LEN + k];
            seq8[i] = s;
            d->seq = s + 1;
        }
        slot_base[i] = (uint32_t)i * rl->slot_size;
        uint8_t *slot = rl->arena + slot_base[i];
        build_aad(slot, seq8[i], ct_len[i], 0);
        memcpy(slot + ZXREC_AAD_OFF,
               p + ZXREC_TLS_HDR_LEN + ZXREC_EXPLICIT_IV_LEN,
               ct_len[i] + ZXREC_TAG_LEN);

        uint8_t nonce12[ZXREC_NONCE_LEN];
        build_nonce(d, nonce12, seq8[i]);
        rl_fill_req(&reqs[i], d->sess_id, slot_base[i], ct_len[i],
                    nonce12, ZXREC_AAD_LEN, 1);
    }

    int ret = rl_submit(rl, reqs, n);
    if (ret)
        return ret;
    rl->open_ops += (unsigned long)n;

    /* tag 校验在软件做（硬件把重算 tag 写回槽内，见上方注释） */
    if (zx_sw_tag()) {
        for (int i = 0; i < n; i++) {
            const uint8_t *wire_tag = (const uint8_t *)in[i].iov_base
                                      + ZXREC_TLS_HDR_LEN
                                      + ZXREC_EXPLICIT_IV_LEN + ct_len[i];
            const uint8_t *hw_tag = rl->arena + slot_base[i] + ZXREC_AAD_OFF + ct_len[i];
            if (memcmp(hw_tag, wire_tag, ZXREC_TAG_LEN) != 0) {
                ZXDBG("open_tls[%d]: tag mismatch (seq %llu)\n",
                      i, (unsigned long long)seq8[i]);
                if (zxdbg()) {
                    uint8_t *base = rl->arena + slot_base[i] + ZXREC_AAD_OFF;
                    fprintf(stderr, "[zxdbg]   wire_tag: ");
                    for (int k = 0; k < 16; k++) fprintf(stderr, "%02x", wire_tag[k]);
                    fprintf(stderr, "\n[zxdbg]   dump slot+128+ct-8 .. +56:\n");
                    for (int k = 0; k < 64; k++) {
                        fprintf(stderr, "%02x%s", base[(ssize_t)ct_len[i] - 8 + k],
                                (k % 16 == 15) ? "\n" : " ");
                    }
                }
                return -EBADMSG;
            }
        }
    }
    for (int i = 0; i < n; i++) {
        out[i].iov_base = rl->arena + slot_base[i] + ZXREC_AAD_OFF;
        out_lens[i] = (int)ct_len[i];
    }
    return 0;
}

int zxsec_rl_stream_parse(const uint8_t *buf, size_t len,
                          struct iovec *recs, int *n_recs,
                          uint8_t *types, size_t *consumed)
{
    size_t pos = 0;
    int n = 0;

    while (pos + ZXREC_TLS_HDR_LEN <= len && n < ZXREC_MAX_BATCH) {
        size_t payload = ((size_t)buf[pos + 3] << 8) | buf[pos + 4];
        size_t total = ZXREC_TLS_HDR_LEN + payload;
        if (pos + total > len)
            break;                       /* 半包，等下一次读 */
        recs[n].iov_base = (void *)(buf + pos);
        recs[n].iov_len  = total;
        types[n] = buf[pos];
        n++;
        pos += total;
    }
    *n_recs = n;
    *consumed = pos;
    return 0;
}
