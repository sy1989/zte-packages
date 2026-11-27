/*
 * zxsec-record.h - openconnect 批量记录层（路线 2 + 路径 A 直连 ioctl）
 *
 * 角色：openconnect 数据面（DTLS/CSTP）自管的 TLS1.2 / DTLS1.2 AES-GCM
 * 记录编解码器，底层走 /dev/zx279133-sec 的 SUBMIT_BATCH ioctl（≤16 条
 * 记录一次提交，arena mmap 零中间层）。
 *
 * 密码学约定（OpenSSL 3.5.7 源码实证，见 设计文档.md 1.4 节）：
 *   nonce(12B) = salt(4) ‖ seq(8B BE)          RFC5288，无 XOR，nonce 不上线
 *   AAD(13B)   = seq(8B BE) ‖ type(1) ‖ ver(2) ‖ ct_len_be16(2)
 *   DTLS: seq8 = epoch(2) ‖ seq48(6)；记录头 13B = type,ver(FEFD),epoch,seq6,len
 *   TLS  记录头 5B = type(0x17), ver(0303), ct_len
 *
 * 线程模型：所有接口只允许主循环单线程调用（与 openconnect mainloop 一致）。
 *
 * 返回约定：0 成功；<0 失败（-EIO 设备错误，-EBADMSG = 解密 tag 校验失败）。
 */
#ifndef ZXSEC_RECORD_H
#define ZXSEC_RECORD_H

#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#define ZXREC_MAX_BATCH   16
#define ZXREC_TAG_LEN     16
#define ZXREC_SALT_LEN    4
#define ZXREC_EXPLICIT_IV_LEN 8   /* TLS/DTLS 1.2 AEAD 记录体内的显式 nonce */
#define ZXREC_IV13_LEN    12      /* TLS1.3 write_iv（static IV）长度 */
#define ZXREC_NONCE_LEN   12
#define ZXREC_AAD_LEN     13      /* TLS1.2: seq(8)||type||ver||len */
#define ZXREC_AAD13_LEN   5       /* TLS1.3: AAD 就是 5B 记录头 */
#define ZXREC_TLS_HDR_LEN 5
#define ZXREC_DTLS_HDR_LEN 13
/* 一条 TLS1.2 AEAD 记录的固定开销：5B 头 + 8B 显式 nonce + 16B tag */
#define ZXREC_OVERHEAD    (ZXREC_TLS_HDR_LEN + ZXREC_EXPLICIT_IV_LEN + ZXREC_TAG_LEN)

struct zxsec_rl;

/* 打开设备 + mmap arena。失败返回负 errno。 */
int  zxsec_rl_init(struct zxsec_rl **out);
void zxsec_rl_close(struct zxsec_rl *rl);

/*
 * 安装记录密钥（来自 libssl t1_enc.c 钩子 oc_zxsec_on_keys）。
 *   dir:      0 = 读方向（RX 解密），1 = 写方向（TX 加密）
 *   keylen:   16 或 32（AES-128/256-GCM）
 *   salt:     4 字节固定 IV（key block 中 GCM 的 iv 就是这 4 字节）
 *   epoch:    DTLS 写方向的 epoch（TLS 忽略）；新 epoch 时 seq 归零
 *   is_dtls:  1 = DTLS 通道, 0 = CSTP/TLS 通道
 */
int zxsec_rl_set_key(struct zxsec_rl *rl, int dir,
                     const uint8_t *key, int keylen,
                     const uint8_t *salt, uint16_t epoch, int is_dtls);

/*
 * TLS1.3 版密钥安装（RFC 8446 application traffic key）：
 *   dir:      0 = 读方向，1 = 写方向
 *   keylen:   16 或 32（AES-128/256-GCM）
 *   iv12:     12 字节 static IV（TLS1.3 没有 4B salt 的概念）
 * 安装后该方向走 TLS1.3 记录格式（见下），序号两方向都从 0 起
 * （application traffic key 是全新的密钥空间）。只用于 CSTP/TCP 通道；
 * DTLS 侧始终 DTLS1.2（ocserv/openconnect 不协商 DTLS1.3）。
 */
int zxsec_rl_set_key13(struct zxsec_rl *rl, int dir,
                       const uint8_t *key, int keylen,
                       const uint8_t *iv12);

/* 覆盖当前序号计数器（GnuTLS 握手完成后需要按它的 sequence_number 对齐；
 * OpenSSL 路径不需要调用，set_key() 的默认行为保持原样）。 */
void zxsec_rl_set_seq(struct zxsec_rl *rl, int dir, uint64_t seq);

/*
 * 批量加密：n（≤16）个明文 → 连续输出缓冲里的 n 条 TLS/DTLS 记录。
 * is_dtls=1 时同时填充 dgram_out[i]（每条记录一个独立数据报，
 * 供 sendmmsg 使用），记录头带 epoch/seq。
 * 返回 0 成功；*outlen 为总输出长度。
 */
int zxsec_rl_seal(struct zxsec_rl *rl, int is_dtls,
                  const struct iovec *in, int n,
                  uint8_t *out, size_t outcap, size_t *outlen,
                  struct iovec *dgram_out, int max_dgrams, int *n_dgrams);

/*
 * 批量解密（DTLS）：in[i] = 一个 UDP 数据报（= 一条 DTLS 记录）。
 *   out[i]/out_lens[i] = 明文（不含 1 字节 AC_PKT 类型头，那是记录外层的
 *   openconnect 约定，由调用方自己处理）；types[i] = 记录类型（0x17 才是数据）。
 * 返回 0；某条记录 tag 校验失败返回 -EBADMSG（调用方应断链重连）。
 */
int zxsec_rl_open_dtls(struct zxsec_rl *rl,
                       const struct iovec *in, int n,
                       struct iovec *out, int *out_lens, uint8_t *types);

/*
 * 批量解密（CSTP/TLS）：in = 连续字节流切片（已按 5B 记录头切好，
 * 记录含头），n 条记录一次解密。
 * TLS1.2：seq 来自记录体内的显式 nonce；types[i] = 记录头 type。
 * TLS1.3（set_key13 安装后）：seq 用内部计数器（两方向都从 0 起）；
 *   外层记录头恒为 0x17，真正的类型加密在明文尾部——解密后从明文尾部
 *   找最后一个非 0 字节填入 types[i]（0x17=数据，0x15=alert，
 *   0x16=handshake/KeyUpdate），out_lens[i] 为去掉类型与 padding 后的
 *   有效明文长度。types 可传 NULL（1.2 下忽略）。
 * 输出 out[i] = 记录明文（不含 5B 头）。
 */
int zxsec_rl_open_tls(struct zxsec_rl *rl,
                      const struct iovec *in, int n,
                      struct iovec *out, int *out_lens,
                      uint8_t *types);

/* 从连续缓冲里解析出完整记录（含头），返回消耗的字节数；
 * recs[i] 指向记录头起始。rec_n 上限 ZXREC_MAX_BATCH。
 * 遇到非 0x17 记录也照常返回（调用方决定怎么处理）。 */
int zxsec_rl_stream_parse(const uint8_t *buf, size_t len,
                          struct iovec *recs, int *n_recs,
                          uint8_t *types, size_t *consumed);

/* 调试统计 */
void zxsec_rl_stats(struct zxsec_rl *rl, unsigned long *seal_ops,
                    unsigned long *open_ops, unsigned long *batches);

#endif /* ZXSEC_RECORD_H */
