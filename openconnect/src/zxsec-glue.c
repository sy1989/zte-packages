/*
 * zxsec-glue.c - openconnect 与 zxsec-record codec 的粘合层
 *
 * 职责：
 *   1. 实现 TLS 库的密钥钩子（OpenSSL: oc_zxsec_on_keys()；GnuTLS:
 *      oc_zxsec_gnutls_on_keys()），按会话对象路由密钥到 DTLS/CSTP codec。
 *   2. 提供 zxsec_dtls_read/write 批量读写封装与 TX 批量发送，
 *      dtls_mainloop 只需要极小的改动点。
 *
 * 安全边界：
 *   - codec 只在握手协商出 DTLS1.2 + AES-GCM 时启用（zxsec_glue_dtls_check），
 *     其余情况行为与原版 openconnect 完全一致。
 *   - 所有失败路径都降级回原版逻辑（禁用 codec / 重连），不半途切换。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef OPENCONNECT_OPENSSL
#include <openssl/ssl.h>
#elif defined(OPENCONNECT_GNUTLS)
#include <gnutls/gnutls.h>
#endif

#include "openconnect-internal.h"
#include "zxsec-record.h"
#include "zxsec-glue.h"
#include "zxsec_uapi.h"

/* 两个后端都用 vpninfo->dtls_ssl 保存数据报会话；HTTPS 会话的字段名不同。
 * 用 void * 比较只是为了给自管记录层一个“连接身份”，不做任何解引用。 */
#ifdef OPENCONNECT_OPENSSL
#define ZX_HTTPS_SESSION(v) ((void *)(v)->https_ssl)
#else
#define ZX_HTTPS_SESSION(v) ((void *)(v)->https_sess)
#endif
#define ZX_DTLS_SESSION(v) ((void *)(v)->dtls_ssl)

/* GnuTLS 补丁导出的辅助函数：返回当前 epoch 的记录序号（还没用于下一条记录）。
 * 弱引用让同一份 glue 在纯 OpenSSL 构建里也能编译。 */
extern int oc_zxsec_gnutls_get_seq(void *session, uint64_t *read_seq,
				   uint64_t *write_seq)
#ifdef OPENCONNECT_GNUTLS
	__attribute__((weak))
#endif
	;

#define RX_DGRAM 6             /* 每次 recvmmsg 收的数据报数 */
#define RX_RECS  ZXREC_MAX_BATCH /* 展开后单批记录上限（= 硬件 max_batch） */
#define RX_BUF   1700          /* > MTU；DTLS 数据报上限 */

/* CSTP/TCP：记录上限 16K 明文，但 TCP 一次 read 可能带回多条记录 */
#define CSTP_MAX_PLAIN 16384
#define CSTP_RXBUF  (64 * 1024)
#define CSTP_MAXREC (CSTP_MAX_PLAIN + ZXREC_OVERHEAD)
#define CSTP_PLBUF  (272 * 1024)   /* 一批最多 16 条 × 16K 明文 */
#define CSTP_AGGMAX (32 * 1024)    /* 上行一批最多攒 32KB（≤16 帧，每帧一条记录） */
#define CSTP_TXBUF  (CSTP_AGGMAX + 16 * ZXREC_OVERHEAD + 256)

/* 握手阶段 vpninfo 还没注册（TCP-only 时 dtls glue 根本不会初始化），
 * 先把 https_ssl 的 key/salt 暂存，等 cstp_connect() 里 bind 时再装。 */
struct zxsec_pending_key {
	void *ssl;
	int have;
	int keylen;
	uint8_t key[32];
	uint8_t salt[ZXREC_SALT_LEN];
	/* TLS1.3（RFC 8446）：没有 4B salt，只有 12B static IV。tls13=1 时
	 * bind 走 zxsec_rl_set_key13()，记录层进入 1.3 记录格式。 */
	int tls13;
	uint8_t iv13[ZXREC_IV13_LEN];
};

struct zxsec_glue {
	int enabled;                       /* DTLS gate 通过后置 1 */
	int dtls_key[2];                   /* DTLS 0=read 1=write 已从库钩子装 key */
	int tls_active;                    /* CSTP gate 通过后置 1 */
	int tls_key[2];                    /* CSTP 0=read 1=write 已装 key */
	int tls13;                         /* CSTP 协商的是 TLS1.3 */
	void *tls_ssl;                     /* bind 时的 https_ssl，防串连接 */
	struct zxsec_rl *rl;
	struct zxsec_rl *tls_rl;
	struct openconnect_info *vpninfo;
	struct zxsec_pending_key pend[2];

	/* CSTP 接收：记录缓冲 + 当前记录的明文（arena 槽会被下一次 seal 覆盖，
	 * 必须拷出来） */
	uint8_t *tls_rxbuf;
	size_t tls_rxoff, tls_rxlen;
	uint8_t *tls_plbuf;
	int tls_pl_n, tls_pl_idx;                       /* 已解密的记录队列 */
	size_t tls_pl_off[ZXREC_MAX_BATCH];
	size_t tls_pl_len[ZXREC_MAX_BATCH];
	size_t tls_pl_pos[ZXREC_MAX_BATCH];
	uint8_t *tls_txbuf;
	size_t tls_tx_len;                 /* 已封装的记录长度 */
	size_t tls_tx_off;                 /* 已写出多少（非阻塞续写） */
	size_t tls_tx_done;                /* 本轮封完后覆盖到的明文偏移 */
	int tls_tx_plen;                   /* 对应上层那次写的长度 */
	int tls_tx_batch;                  /* 已封装数据是否覆盖了整个调用 */
	uint8_t *tls_agg;                  /* 上行攒批暂存（CSTP_AGGMAX） */

	/* RX 批量缓存 */
	uint8_t *rxbuf[RX_DGRAM];          /* recvmmsg 接收缓冲（每个数据报一块） */
	struct iovec rxiov[RX_DGRAM];
	struct mmsghdr rxmsg[RX_DGRAM];
	struct iovec reciov[RX_RECS];      /* 记录级视图：指向数据报内部 */
	struct iovec plain[RX_RECS];       /* 解密输出 */
	int plain_len[RX_RECS];
	uint8_t types[RX_RECS];
	int cached;                        /* 当前缓存里待取的记录数 */
	int cached_off;
};

static struct zxsec_glue g_zx;

int zxsec_glue_available(void)
{
	/* ZXSEC_DISABLE=1：强制走原生 OpenSSL 路径（A/B 对比基线） */
	if (getenv("ZXSEC_DISABLE"))
		return 0;
	return g_zx.enabled && g_zx.rl;
}

/* -------------------- TLS 库密钥钩子 -------------------- */

/* 两个后端共用的密钥分发：ssl 参数是会话对象（SSL* 或 gnutls_session_t）。 */
static void zxsec_on_keys(void *ssl, int is_dtls, int is_write, uint16_t epoch,
			  const unsigned char *key, size_t key_len,
			  const unsigned char *iv, size_t iv_len)
{
	struct openconnect_info *vpninfo = g_zx.vpninfo;
	int dir = is_write ? 1 : 0;

	if (iv_len != ZXREC_SALT_LEN || (key_len != 16 && key_len != 32))
		return;

	if (!is_dtls) {
		/* CSTP/TLS：握手时 vpninfo 可能还没注册，先按会话对象暂存 */
		struct zxsec_pending_key *p = &g_zx.pend[dir];

		p->ssl = ssl;
		p->have = 1;
		p->keylen = (int)key_len;
		memcpy(p->key, key, key_len);
		memcpy(p->salt, iv, ZXREC_SALT_LEN);

		if (g_zx.tls_active && g_zx.tls_rl && ssl == g_zx.tls_ssl &&
		    !zxsec_rl_set_key(g_zx.tls_rl, dir, key, (int)key_len, iv, 0, 0)) {
			g_zx.tls_key[dir] = 1;
#ifdef OPENCONNECT_GNUTLS
			/* 重协商会走到这里；GnuTLS 的新 epoch 序号不固定为 1。 */
			if (is_write && oc_zxsec_gnutls_get_seq) {
				uint64_t wseq = 0;
				if (oc_zxsec_gnutls_get_seq(ssl, NULL, &wseq) == 0)
					zxsec_rl_set_seq(g_zx.tls_rl, 1, wseq);
			}
#endif
			if (vpninfo)
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("ZXSEC: CSTP %s keys reinstalled\n"),
					     is_write ? "write" : "read");
		}
		return;
	}

	if (!vpninfo || !g_zx.rl)
		return;
	if (ssl != ZX_DTLS_SESSION(vpninfo))
		return;

	if (zxsec_rl_set_key(g_zx.rl, is_write, key, (int)key_len, iv, epoch, 1)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: DTLS %s key install failed, batching disabled\n"),
			     is_write ? "write" : "read");
		g_zx.dtls_key[dir] = 0;
		return;
	}
	g_zx.dtls_key[dir] = 1;
#ifdef OPENCONNECT_GNUTLS
	/* 重密钥时同样按 GnuTLS 当前序号对齐（DTLS 高 16 位是 epoch）。 */
	if (is_write && oc_zxsec_gnutls_get_seq) {
		uint64_t wseq = 0;
		if (oc_zxsec_gnutls_get_seq(ssl, NULL, &wseq) == 0)
			zxsec_rl_set_seq(g_zx.rl, 1, wseq & 0xffffffffffffULL);
	}
#endif
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("ZXSEC: DTLS %s keys installed (epoch %u)\n"),
		     is_write ? "write" : "read", epoch);
}

#ifdef OPENCONNECT_OPENSSL
/* libssl t1_enc.c: tls1_change_cipher_state() 末尾的弱符号钩子 */
void oc_zxsec_on_keys(SSL *ssl, int is_dtls, int is_write,
		      uint16_t w_epoch,
		      const unsigned char *key, size_t key_len,
		      const unsigned char *iv, size_t iv_len)
{
	zxsec_on_keys((void *)ssl, is_dtls, is_write, w_epoch,
		      key, key_len, iv, iv_len);
}
#endif

#ifdef OPENCONNECT_GNUTLS
/*
 * GnuTLS constate.c: _gnutls_set_keys() 末尾的弱符号钩子。
 * 只会在 TLS1.2/DTLS1.2 密钥派生时触发（TLS1.3 走 _tls13_set_keys）。
 */
void oc_zxsec_gnutls_on_keys(void *session, int is_dtls, int epoch,
			     int is_write,
			     const unsigned char *key, size_t key_len,
			     const unsigned char *iv, size_t iv_len,
			     int cipher_id, int version_id)
{
	(void)version_id;

	/* 只接管 TLS1.2 风格的 GCM：salt(4)||seq(8)，无 XOR nonce。
	 * AES-128/256-GCM 的公开枚举值见 gnutls/gnutls.h。 */
	if (cipher_id != GNUTLS_CIPHER_AES_128_GCM &&
	    cipher_id != GNUTLS_CIPHER_AES_256_GCM)
		return;
	if (!is_dtls && version_id != GNUTLS_TLS1_2)
		return;
	if (is_dtls && version_id != GNUTLS_DTLS1_2)
		return;

	zxsec_on_keys(session, is_dtls, is_write, (uint16_t)epoch,
		      key, key_len, iv, iv_len);
}
#endif

/* -------------------- TLS1.3 密钥钩子 -------------------- */

/*
 * TLS1.3 与 1.2 的差别（RFC 8446 §5.2 / §7.3）：
 *   - 没有 4B salt：密钥 = key + 12B static IV，nonce = iv XOR seq；
 *   - application traffic key 是全新的密钥空间，两方向 seq 都从 0 起
 *     （client Finished 用的是 handshake traffic key，另一把 key）；
 *   - 外层记录头恒为 0x17/0x0303，真正的类型在密文内部，解密后从
 *     明文尾部取（0x17 数据 / 0x15 alert / 0x16 handshake=KeyUpdate）。
 * 只接 application traffic key：handshake 级密钥由库自己用（接管点在
 * 握手完成之后）。DTLS 1.3 不做（ocserv/openconnect 不协商）。
 */
static void zxsec_on_keys13(void *ssl, int is_write,
			    const unsigned char *key, size_t key_len,
			    const unsigned char *iv, size_t iv_len)
{
	struct openconnect_info *vpninfo = g_zx.vpninfo;
	int dir = is_write ? 1 : 0;

	if (iv_len != ZXREC_IV13_LEN || (key_len != 16 && key_len != 32))
		return;

	/* 与 1.2 相同：握手阶段先按会话对象暂存 */
	struct zxsec_pending_key *p = &g_zx.pend[dir];

	p->ssl = ssl;
	p->have = 1;
	p->keylen = (int)key_len;
	p->tls13 = 1;
	memcpy(p->key, key, key_len);
	memcpy(p->iv13, iv, ZXREC_IV13_LEN);

	if (g_zx.tls_active && g_zx.tls_rl && ssl == g_zx.tls_ssl &&
	    !zxsec_rl_set_key13(g_zx.tls_rl, dir, key, (int)key_len, iv)) {
		g_zx.tls_key[dir] = 1;
		if (vpninfo)
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("ZXSEC: CSTP TLS1.3 %s keys reinstalled\n"),
				     is_write ? "write" : "read");
	}
}

#ifdef OPENCONNECT_OPENSSL
/* libssl tls13_enc.c: tls13_change_cipher_state() 末尾（application 级）
 * 的弱符号钩子，见 openssl 170 号补丁。 */
void oc_zxsec_on_keys13(SSL *ssl, int is_write,
			const unsigned char *key, size_t key_len,
			const unsigned char *iv, size_t iv_len)
{
	zxsec_on_keys13((void *)ssl, is_write, key, key_len, iv, iv_len);
}
#endif

#ifdef OPENCONNECT_GNUTLS
/*
 * GnuTLS constate.c: _tls13_set_keys() 末尾的弱符号钩子（110 号补丁）。
 * is_app 区分 STAGE_APP（application traffic key）与 STAGE_HS（握手级）——
 * 只接前者。STAGE_UPD_*（KeyUpdate）走 _tls13_update_keys()，不经过这里；
 * 读方向遇到 inner handshake 记录时按不支持处理（断线重连）。
 */
void oc_zxsec_gnutls13_on_keys(void *session, int is_write,
			       const unsigned char *key, unsigned key_len,
			       const unsigned char *iv, unsigned iv_len,
			       int cipher_id, int is_app)
{
	if (!is_app)
		return;
	if (cipher_id != GNUTLS_CIPHER_AES_128_GCM &&
	    cipher_id != GNUTLS_CIPHER_AES_256_GCM)
		return;

	zxsec_on_keys13(session, is_write, key, key_len, iv, iv_len);
}
#endif

/* -------------------- 生命周期 -------------------- */

void zxsec_glue_dtls_init(struct openconnect_info *vpninfo)
{
	g_zx.vpninfo = vpninfo;
	if (!g_zx.rl && zxsec_rl_init(&g_zx.rl)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: cannot open %s, batching disabled\n"),
			     ZXSEC_DEV_SEC);
		return;
	}
	if (!g_zx.rxbuf[0]) {
		for (int i = 0; i < RX_DGRAM; i++)
			g_zx.rxbuf[i] = malloc(RX_BUF);
	}
	memset(g_zx.rxmsg, 0, sizeof(g_zx.rxmsg));
	for (int i = 0; i < RX_DGRAM; i++) {
		g_zx.rxiov[i].iov_base = g_zx.rxbuf[i];
		g_zx.rxiov[i].iov_len  = RX_BUF;
		g_zx.rxmsg[i].msg_hdr.msg_iov    = &g_zx.rxiov[i];
		g_zx.rxmsg[i].msg_hdr.msg_iovlen = 1;
	}
	g_zx.cached = 0;
	g_zx.enabled = 0;		/* 等 gate 检查 */
	g_zx.dtls_key[0] = g_zx.dtls_key[1] = 0; /* 等库钩子送 key */
}

/* 握手完成后调用：协商 DTLS1.2 + AES-GCM 才启用。
 * GnuTLS 的写序号在握手记录里已经前进，启用时必须按它的值对齐。 */
void zxsec_glue_dtls_check(struct openconnect_info *vpninfo)
{
	void *ssl = ZX_DTLS_SESSION(vpninfo);
	int ok = 0;
	const char *cipher_name = "AES-GCM";

	if (getenv("ZXSEC_DISABLE")) {
		g_zx.enabled = 0;
		return;
	}
	if (!g_zx.rl || !ssl) {
		g_zx.enabled = 0;
		return;
	}
#ifdef OPENCONNECT_OPENSSL
	{
		const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
		int nid;

		if (SSL_version(ssl) == DTLS1_2_VERSION && c) {
			nid = SSL_CIPHER_get_cipher_nid(c);
			ok = (nid == NID_aes_128_gcm || nid == NID_aes_256_gcm);
			cipher_name = SSL_CIPHER_get_name(c);
		}
	}
#elif defined(OPENCONNECT_GNUTLS)
	{
		gnutls_cipher_algorithm_t c = gnutls_cipher_get(ssl);

		ok = (gnutls_protocol_get_version(ssl) == GNUTLS_DTLS1_2 &&
		      (c == GNUTLS_CIPHER_AES_128_GCM ||
		       c == GNUTLS_CIPHER_AES_256_GCM));
		if (c == GNUTLS_CIPHER_AES_128_GCM)
			cipher_name = "AES-128-GCM";
		else if (c == GNUTLS_CIPHER_AES_256_GCM)
			cipher_name = "AES-256-GCM";
	}
#endif
	if (!ok) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("ZXSEC: DTLS version/cipher not AES-GCM/DTLS1.2, batching disabled\n"));
		g_zx.enabled = 0;
		return;
	}

	/* key-ready 门：TLS 库必须真的把 key/salt 送到钩子并装进 codec。
	 * 若混用了没打 keyhook 的 stock libssl/libgnutls，钩子不会被调用，
	 * dtls_key[] 仍为 0——此时必须禁用，否则会打出 ENABLED 日志却无法
	 * 解密（数据面拿不到 key）。这是与 CSTP 相同的就绪检查。 */
	if (!g_zx.dtls_key[0] || !g_zx.dtls_key[1]) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("ZXSEC: DTLS keys not captured by keyhook (stock TLS library?), batching disabled\n"));
		g_zx.enabled = 0;
		return;
	}

#ifdef OPENCONNECT_GNUTLS
	if (oc_zxsec_gnutls_get_seq) {
		uint64_t wseq = 0;
		if (oc_zxsec_gnutls_get_seq(ssl, NULL, &wseq) == 0)
			zxsec_rl_set_seq(g_zx.rl, 1, wseq & 0xffffffffffffULL);
	}
#endif
	g_zx.enabled = 1;
	vpn_progress(vpninfo, PRG_INFO,
		     _("ZXSEC: DTLS batch record layer ENABLED (%s)\n"),
		     cipher_name);
}

void zxsec_glue_dtls_disable(void)
{
	g_zx.enabled = 0;
	g_zx.cached = 0;
	/* 重连会重新握手、keyhook 重新装 key；先清掉旧epoch的就绪标志，
	 * 避免 stock 库场景下残留的 1 让 gate 误判。 */
	g_zx.dtls_key[0] = g_zx.dtls_key[1] = 0;
}

/* -------------------- RX 批量 -------------------- */

/*
 * ocserv 会把多条 DTLS 记录合并进同一个 UDP 数据报（实测 1687 字节的
 * 数据报里含 2 条应用数据记录）。这里按记录头逐条切开，只保留应用数据
 * （0x17）—— 握手/CCS/alert 不经过批量层。返回可解密记录数。
 */
static int flatten_dtls(struct zxsec_glue *g, int ndgram)
{
	int out = 0;

	for (int i = 0; i < ndgram && out < RX_RECS; i++) {
		uint8_t *p = g->rxbuf[i];
		size_t len = g->rxmsg[i].msg_len;
		size_t off = 0;

		while (off + ZXREC_DTLS_HDR_LEN <= len) {
			const uint8_t *h = p + off;
			size_t rlen = ((size_t)h[11] << 8) | h[12];

			if (off + ZXREC_DTLS_HDR_LEN + rlen > len)
				break;		/* 截断的记录，整报丢弃剩余部分 */
			if (h[0] == 0x17 /* application_data */
			    && rlen >= ZXREC_EXPLICIT_IV_LEN + ZXREC_TAG_LEN) {
				if (out >= RX_RECS)
					break;
				g->reciov[out].iov_base = (void *)h;
				g->reciov[out].iov_len  = ZXREC_DTLS_HDR_LEN + rlen;
				out++;
			}
			off += ZXREC_DTLS_HDR_LEN + rlen;
		}
	}
	return out;
}

/* 返回值：>0 = 记录长度（buf 已填 1B AC_PKT 类型 + 明文，与原版 ssl_nonblock_read
 *          的返回格式完全一致）；0 = 暂无数据；<0 = 错误（调用方重连） */
int zxsec_dtls_read(struct openconnect_info *vpninfo, unsigned char *buf,
		    int maxlen)
{
	struct zxsec_glue *g = &g_zx;

	while (g->cached_off >= g->cached) {
		int n, r;

		g->cached = 0;
		g->cached_off = 0;
		n = recvmmsg(vpninfo->dtls_fd, g->rxmsg, RX_DGRAM,
			     MSG_DONTWAIT, NULL);
		if (n <= 0)
			return 0;		/* EAGAIN / 无数据 */
		n = flatten_dtls(g, n);
		if (n == 0)
			continue;		/* 本批全是非应用数据，继续收 */
		r = zxsec_rl_open_dtls(g->rl, g->reciov, n,
				       g->plain, g->plain_len, g->types);
		if (r) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("ZXSEC: DTLS batch decrypt failed: %s\n"),
				     strerror(-r));
			return -EIO;
		}
		g->cached = n;
	}

	{
		int i = g->cached_off;

		if (g->types[i] != 0x17) {
			/* 非应用数据记录（alert 等）：与原版行为一致，重连 */
			vpn_progress(vpninfo, PRG_ERR,
				     _("ZXSEC: non-app DTLS record type %02x\n"),
				     g->types[i]);
			return -EIO;
		}
		if (g->plain_len[i] + 1 > maxlen)
			return -EIO;
		/* 明文 = 1B AC_PKT 类型 + payload，直接还原原版格式 */
		memcpy(buf, g->plain[i].iov_base, g->plain_len[i]);
		g->cached_off++;
		return g->plain_len[i];
	}
}

/* -------------------- TX -------------------- */

/* 单条记录写（keepalive/DPD 等控制包），走 codec 保持 seq 一致 */
int zxsec_dtls_write(struct openconnect_info *vpninfo, void *buf, int len)
{
	struct zxsec_glue *g = &g_zx;
	struct iovec in = { buf, (size_t)len };
	uint8_t outbuf[1700];
	size_t outlen = 0;
	struct iovec dgram[1];
	int nd = 0;
	int r;

	r = zxsec_rl_seal(g->rl, 1, &in, 1, outbuf, sizeof(outbuf), &outlen,
			  dgram, 1, &nd);
	if (r) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: DTLS seal failed: %s\n"), strerror(-r));
		return -EIO;
	}
	r = (int)send(vpninfo->dtls_fd, dgram[0].iov_base, dgram[0].iov_len,
		      MSG_DONTWAIT);
	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			monitor_write_fd(vpninfo, dtls);
			return 0;
		}
		return -EIO;
	}
	return len;
}

/* MTU 探测/keepalive 使用的阻塞语义包装（openconnect_dtls_read/write）。 */
int zxsec_dtls_write_wait(struct openconnect_info *vpninfo, void *buf, int len)
{
	int r = zxsec_dtls_write(vpninfo, buf, len);

	while (r == 0) {
		struct pollfd pfd = { .fd = vpninfo->dtls_fd,
				      .events = POLLOUT, .revents = 0 };
		int pr;

		do {
			pr = poll(&pfd, 1, -1);
		} while (pr < 0 && errno == EINTR);
		if (pr < 0)
			return -EIO;
		r = zxsec_dtls_write(vpninfo, buf, len);
	}
	return r;
}

int zxsec_dtls_read_wait(struct openconnect_info *vpninfo, void *buf, int len,
			 unsigned ms)
{
	struct timeval start, now;
	unsigned elapsed = 0;

	gettimeofday(&start, NULL);
	for (;;) {
		int r = zxsec_dtls_read(vpninfo, buf, len);

		if (r != 0)
			return r;
		if (ms) {
			gettimeofday(&now, NULL);
			elapsed = (unsigned)((now.tv_sec - start.tv_sec) * 1000 +
					     (now.tv_usec - start.tv_usec) / 1000);
			if (elapsed >= ms)
				return -ETIMEDOUT;
		}
		{
			struct pollfd pfd = { .fd = vpninfo->dtls_fd,
					      .events = POLLIN, .revents = 0 };
			int timeout = ms ? (int)(ms - elapsed) : -1;
			int pr;

			do {
				pr = poll(&pfd, 1, timeout);
			} while (pr < 0 && errno == EINTR);
			if (pr < 0)
				return -EIO;
			if (!pr)
				return -ETIMEDOUT;
		}
	}
}

/*
 * TX 批量：一次榨干 outgoing_queue（≤16 包）→ 一次 SUBMIT_BATCH → sendmmsg。
 * 返回值与原版循环语义兼容：>0 发送包数；0 = EAGAIN（已 requeue）；<0 错误。
 * 注意：DTLS 压缩启用时不做批量（deflate_pkt 是共享单缓冲），返回 -ENOSYS
 * 由调用方回退逐包路径。
 */
int zxsec_dtls_tx_batch(struct openconnect_info *vpninfo)
{
	struct zxsec_glue *g = &g_zx;
	struct pkt *pkts[RX_RECS];
	struct iovec in[RX_RECS], dgram[RX_RECS];
	struct mmsghdr msg[RX_RECS];
	uint8_t outbuf[RX_RECS * 1700];
	size_t outlen = 0;
	int np = 0, n_dgrams = 0, sent, r;

	if (vpninfo->dtls_compr)
		return -ENOSYS;

	while (vpninfo->outgoing_queue.head && np < RX_RECS) {
		struct pkt *this = dequeue_packet(&vpninfo->outgoing_queue);

		if (vpninfo->dtls_tos_optname)
			udp_tos_update(vpninfo, this);
		this->cstp.hdr[7] = AC_PKT_DATA;
		in[np].iov_base = &this->cstp.hdr[7];   /* 1B 类型 + payload */
		in[np].iov_len  = (size_t)this->len + 1;
		pkts[np++] = this;
	}
	if (!np)
		return 0;

	r = zxsec_rl_seal(g->rl, 1, in, np, outbuf, sizeof(outbuf), &outlen,
			  dgram, np, &n_dgrams);
	if (r) {
		/* 失败：按逆序 requeue，保持原顺序 */
		for (int i = np - 1; i >= 0; i--)
			requeue_packet(&vpninfo->outgoing_queue, pkts[i]);
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: DTLS batch seal failed: %s\n"),
			     strerror(-r));
		return -EIO;
	}

	memset(msg, 0, sizeof(msg));
	for (int i = 0; i < n_dgrams; i++) {
		msg[i].msg_hdr.msg_iov = &dgram[i];
		msg[i].msg_hdr.msg_iovlen = 1;
	}

	sent = sendmmsg(vpninfo->dtls_fd, msg, (unsigned int)n_dgrams,
			MSG_DONTWAIT);
	if (sent < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			for (int i = np - 1; i >= 0; i--)
				requeue_packet(&vpninfo->outgoing_queue, pkts[i]);
			monitor_write_fd(vpninfo, dtls);
			return 0;
		}
		for (int i = np - 1; i >= 0; i--)
			requeue_packet(&vpninfo->outgoing_queue, pkts[i]);
		return -EIO;
	}
	for (int i = 0; i < sent; i++)
		free_pkt(vpninfo, pkts[i]);
	if (sent < np) {
		/* 部分发送：剩余按逆序 requeue，保持原顺序 */
		for (int i = np - 1; i >= sent; i--)
			requeue_packet(&vpninfo->outgoing_queue, pkts[i]);
	}
	return sent;
}

/* -------------------- CSTP / TLS1.2 -------------------- */

/*
 * 与 DTLS 的差别：
 *  - 没有数据报边界：一次 read 可能带回多条记录，也可能只有半条；
 *  - 读方向的 seq 来自记录体内的 8B 显式 nonce（OpenSSL 用 seq 填充），
 *    不需要自己维护；写方向按 TLS 库的当前 seq 对齐（OpenSSL 为 1，
 *    GnuTLS 需要读它的 sequence_number），此后所有 application_data
 *    都经过本层，计数器连续；
 *  - 接管点必须在 TLS 握手刚完成时（openconnect_*_connect 尾部）：
 *    认证 POST、HTTP CONNECT 也是普通 application_data，seq 必须从它们
 *    开始连续计数。晚到 CONNECT 前才接管的话，前面那些记录已经把 seq
 *    用掉了，第一条记录就会因 nonce/AAD 里的 seq 不匹配被服务端丢弃
 *    （现象：CONNECT 无响应、连接被关，重连一次反而好了——因为新连接
 *    上 CONNECT 是第一条应用记录）。
 */

int zxsec_cstp_active(struct openconnect_info *vpninfo)
{
	if (!g_zx.tls_active || !g_zx.tls_rl || !g_zx.tls_rxbuf || !g_zx.tls_plbuf)
		return 0;
	if (ZX_HTTPS_SESSION(vpninfo) != g_zx.tls_ssl)
		return 0;
	return 1;
}

/* 连接关闭时调用：清掉与这条 SSL 绑定的全部状态。
 * 不清的话下一个 SSL 可能分到同一地址，zxsec_cstp_active() 会误判成
 * 已经被接管，用旧 key 去解密新连接的数据。 */
void zxsec_glue_tls_unbind(struct openconnect_info *vpninfo)
{
	(void)vpninfo;
	g_zx.tls_active = 0;
	g_zx.tls_ssl = NULL;
	g_zx.tls_key[0] = g_zx.tls_key[1] = 0;
	g_zx.tls13 = 0;
	g_zx.tls_rxoff = g_zx.tls_rxlen = 0;
	g_zx.tls_pl_n = g_zx.tls_pl_idx = 0;
	g_zx.tls_tx_len = g_zx.tls_tx_off = g_zx.tls_tx_done = 0;
	g_zx.tls_tx_plen = 0;
	g_zx.tls_tx_batch = 0;
	g_zx.pend[0].have = g_zx.pend[1].have = 0;
	g_zx.pend[0].tls13 = g_zx.pend[1].tls13 = 0;
}

/* 握手结束后调用一次：装 key、做 gate 检查（TLS1.2 与 TLS1.3 两个分支） */
void zxsec_glue_tls_bind(struct openconnect_info *vpninfo)
{
	void *ssl = ZX_HTTPS_SESSION(vpninfo);
	int ok = 0;
	const char *cipher_name = "AES-GCM";
	int is13;

	g_zx.vpninfo = vpninfo;
	g_zx.tls_active = 0;
	g_zx.tls_key[0] = g_zx.tls_key[1] = 0;
	g_zx.tls13 = 0;
	g_zx.tls_ssl = ssl;
	g_zx.tls_rxoff = g_zx.tls_rxlen = 0;
	g_zx.tls_pl_n = g_zx.tls_pl_idx = 0;

	if (!ssl || getenv("ZXSEC_DISABLE"))
		return;

	if (!g_zx.tls_rxbuf)
		g_zx.tls_rxbuf = malloc(CSTP_RXBUF);
	if (!g_zx.tls_plbuf)
		g_zx.tls_plbuf = malloc(CSTP_PLBUF);
	if (!g_zx.tls_txbuf)
		g_zx.tls_txbuf = malloc(CSTP_TXBUF);
	if (!g_zx.tls_agg)
		g_zx.tls_agg = malloc(CSTP_AGGMAX);
	if (!g_zx.tls_rxbuf || !g_zx.tls_plbuf || !g_zx.tls_txbuf || !g_zx.tls_agg)
		return;

	if (!g_zx.tls_rl && zxsec_rl_init(&g_zx.tls_rl)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: cannot open %s, CSTP offload disabled\n"),
			     ZXSEC_DEV_SEC);
		return;
	}

	/* 两个方向的 pend 必须是同一个 TLS 版本（一次连接不可能混用） */
	is13 = g_zx.pend[0].tls13 || g_zx.pend[1].tls13;
	if ((g_zx.pend[0].have && g_zx.pend[0].tls13 != is13) ||
	    (g_zx.pend[1].have && g_zx.pend[1].tls13 != is13)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("ZXSEC: CSTP mixed TLS version keys, record layer disabled\n"));
		return;
	}
	g_zx.tls13 = is13;

	for (int dir = 0; dir < 2; dir++) {
		struct zxsec_pending_key *p = &g_zx.pend[dir];
		int r;

		if (!p->have || p->ssl != ssl)
			continue;
		if (p->tls13)
			r = zxsec_rl_set_key13(g_zx.tls_rl, dir, p->key,
					       p->keylen, p->iv13);
		else
			r = zxsec_rl_set_key(g_zx.tls_rl, dir, p->key,
					     p->keylen, p->salt, 0, 0);
		if (r) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("ZXSEC: CSTP %s key install failed\n"),
				     dir ? "write" : "read");
			return;
		}
		g_zx.tls_key[dir] = 1;
		if (getenv("ZXSEC_DEBUG"))
			fprintf(stderr,
				"[cstp] bind %s ver=%s key=%02x%02x%02x%02x..%02x iv=%02x%02x%02x%02x ssl=%p\n",
				dir ? "wr" : "rd", p->tls13 ? "tls13" : "tls12",
				p->key[0], p->key[1], p->key[2],
				p->key[3], p->key[p->keylen - 1],
				p->tls13 ? p->iv13[0] : p->salt[0],
				p->tls13 ? p->iv13[1] : p->salt[1],
				p->tls13 ? p->iv13[2] : p->salt[2],
				p->tls13 ? p->iv13[3] : p->salt[3], p->ssl);
	}
	if (!g_zx.tls_key[0] || !g_zx.tls_key[1]) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("ZXSEC: CSTP keys not captured, record layer disabled\n"));
		return;
	}

#ifdef OPENCONNECT_OPENSSL
	{
		const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
		int nid = c ? SSL_CIPHER_get_cipher_nid(c) : NID_undef;

		if (nid == NID_aes_128_gcm || nid == NID_aes_256_gcm) {
			if (is13 && SSL_version(ssl) == TLS1_3_VERSION) {
				ok = 1;
				cipher_name = c ? SSL_CIPHER_get_name(c)
						: "TLS1.3-AES-GCM";
			} else if (!is13 && SSL_version(ssl) == TLS1_2_VERSION) {
				ok = 1;
				cipher_name = c ? SSL_CIPHER_get_name(c) : "AES-GCM";
			}
		}
	}
#elif defined(OPENCONNECT_GNUTLS)
	{
		gnutls_cipher_algorithm_t c = gnutls_cipher_get(ssl);
		gnutls_protocol_t v = gnutls_protocol_get_version(ssl);

		if (c == GNUTLS_CIPHER_AES_128_GCM ||
		    c == GNUTLS_CIPHER_AES_256_GCM) {
			if (is13 && v == GNUTLS_TLS1_3) {
				ok = 1;
				cipher_name = (c == GNUTLS_CIPHER_AES_128_GCM)
					      ? "TLS1.3-AES-128-GCM"
					      : "TLS1.3-AES-256-GCM";
			} else if (!is13 && v == GNUTLS_TLS1_2) {
				ok = 1;
				cipher_name = (c == GNUTLS_CIPHER_AES_128_GCM)
					      ? "AES-128-GCM" : "AES-256-GCM";
			}
		}
	}
#endif
	if (!ok) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("ZXSEC: CSTP version/cipher not supported by record layer, disabled\n"));
		return;
	}

#ifdef OPENCONNECT_GNUTLS
	if (!is13) {
		/* OpenSSL 的 Finished 用掉 seq 0，所以 set_key() 默认从 1 起。
		 * GnuTLS 的握手记录数不固定，直接读取它当前的 sequence_number。
		 * TLS1.3 不需要：application traffic key 是新密钥空间，
		 * set_key13() 已经把两方向 seq 归 0，读 EPOCH_WRITE_CURRENT
		 * 得到的也是同一个值。 */
		if (oc_zxsec_gnutls_get_seq) {
			uint64_t wseq = 0;
			if (oc_zxsec_gnutls_get_seq(ssl, NULL, &wseq) == 0)
				zxsec_rl_set_seq(g_zx.tls_rl, 1, wseq);
		}
	}
#endif

	g_zx.tls_active = 1;
	vpn_progress(vpninfo, PRG_INFO,
		     _("ZXSEC: CSTP batch record layer ENABLED (%s)\n"),
		     cipher_name);
}

static int cstp_write_full(int fd, const uint8_t *p, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return (int)off;	/* 写到哪里算哪里 */
			return -1;
		}
		if (!n)
			return -1;
		off += (size_t)n;
	}
	return (int)len;
}

/* 非阻塞读一次进 rxbuf（顺带把残留移到头部）。
 * 返回 1 = 读到数据；0 = 暂无数据（EAGAIN）；-1 = 致命错误；-2 = 对端关闭。 */
static int cstp_fill(struct zxsec_glue *g, struct openconnect_info *vpninfo)
{
	ssize_t n;

	if (g->tls_rxoff && g->tls_rxlen) {
		memmove(g->tls_rxbuf, g->tls_rxbuf + g->tls_rxoff, g->tls_rxlen);
		g->tls_rxoff = 0;
	} else if (!g->tls_rxlen) {
		g->tls_rxoff = 0;
	}

	if (g->tls_rxlen >= CSTP_RXBUF) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: CSTP rx buffer full without a complete record\n"));
		return -1;
	}

	for (;;) {
		n = read(vpninfo->ssl_fd, g->tls_rxbuf + g->tls_rxlen,
			 CSTP_RXBUF - g->tls_rxlen);
		if (n < 0 && errno == EINTR)
			continue;
		break;
	}

	if (n == 0)
		return -2;
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: CSTP read failed: %s\n"), strerror(errno));
		return -1;
	}

	g->tls_rxlen += (size_t)n;
	return 1;
}

/* 返回约定与 ssl_nonblock_read 一致：>0 字节数；0 = 连接结束；
 * -EAGAIN = 暂无数据（调用方决定等还是当 0）；<0 其他错误。
 *
 * 批量策略：拿到第一条完整记录后先不急着解密，继续非阻塞读把 socket
 * 里已经到达的记录全部抽进 rxbuf，攒到 ZXREC_MAX_BATCH 条或读到 EAGAIN
 * 才发一次 SUBMIT_BATCH。对端没数据时第一次 top-up 就 EAGAIN，所以不会
 * 增加延迟（只是把“立刻到达的”数据合并成一批）。 */
int zxsec_cstp_read(struct openconnect_info *vpninfo, void *buf, int maxlen)
{
	struct zxsec_glue *g = &g_zx;
	int dbg = getenv("ZXSEC_DEBUG") != NULL;
	int drained = 0;	/* 已经试过 top-up 且 socket 里确实没数据了 */

	if (maxlen <= 0)
		return 0;

	/* 队列里还有已解密的记录（http.c 会 1 字节 1 字节地读响应头） */
have_plain:
	if (g->tls_pl_idx < g->tls_pl_n) {
		int i = g->tls_pl_idx;
		size_t left = g->tls_pl_len[i] - g->tls_pl_pos[i];
		size_t n = left;

		if (n > (size_t)maxlen)
			n = (size_t)maxlen;
		memcpy(buf, g->tls_plbuf + g->tls_pl_off[i] + g->tls_pl_pos[i], n);
		g->tls_pl_pos[i] += n;
		if (g->tls_pl_pos[i] >= g->tls_pl_len[i])
			g->tls_pl_idx++;
		return (int)n;
	}

	for (;;) {
		struct iovec recs[ZXREC_MAX_BATCH];
		uint8_t types[ZXREC_MAX_BATCH];
		size_t consumed = 0;
		int nrecs = 0;

		if (g->tls_rxlen >= ZXREC_TLS_HDR_LEN) {
			zxsec_rl_stream_parse(g->tls_rxbuf + g->tls_rxoff,
					      g->tls_rxlen, recs, &nrecs,
					      types, &consumed);

			if (nrecs > 0 && !g->tls13 && types[0] != 0x17) {
				/* alert 当成对端关闭；renegotiation 不支持。
				 * （TLS1.3 外层记录恒为 0x17，不做此检查，
				 * 真正的类型在解密后的明文尾部。） */
				vpn_progress(vpninfo, PRG_ERR,
					     _("ZXSEC: CSTP non-app record type %02x\n"),
					     types[0]);
				return types[0] == 0x15 ? 0 : -EIO;
			}

			if (nrecs > 0 && !drained && nrecs < ZXREC_MAX_BATCH) {
				/* 还装得下一批：先把已到达的数据抽干再解密 */
				int f = cstp_fill(g, vpninfo);

				if (f > 0)
					continue;	/* 又攒到记录，重新解析 */
				if (f < 0 && f != -2)
					return -EIO;
				drained = 1;		/* EOF 留到下一轮再报 */
			}

			if (nrecs > 0) {
				struct iovec out[ZXREC_MAX_BATCH];
				int outlen[ZXREC_MAX_BATCH];
				size_t off = 0;
				int i, r;

				r = zxsec_rl_open_tls(g->tls_rl, recs, nrecs,
						      out, outlen, types);
				if (r) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("ZXSEC: CSTP decrypt failed: %s\n"),
						     strerror(-r));
					return -EIO;
				}
				for (i = 0; i < nrecs; i++) {
					if (outlen[i] < 0
					    || off + (size_t)outlen[i] > CSTP_PLBUF) {
						vpn_progress(vpninfo, PRG_ERR,
							     _("ZXSEC: CSTP plaintext %d out of range\n"),
							     outlen[i]);
						return -EIO;
					}
					memcpy(g->tls_plbuf + off, out[i].iov_base,
					       outlen[i]);
					g->tls_pl_off[i] = off;
					g->tls_pl_len[i] = (size_t)outlen[i];
					g->tls_pl_pos[i] = 0;
					off += (size_t)outlen[i];
				}
				/* TLS1.3：解密后才知道真实类型。KeyUpdate 等
				 * post-handshake 消息不受支持（换 key 没法跟，
				 * 记录层会丢同步）——按连接错误断线重连；
				 * alert 按对端关闭处理。 */
				for (i = 0; i < nrecs; i++) {
					if (g->tls13 && types[i] != 0x17) {
						vpn_progress(vpninfo, PRG_ERR,
							     _("ZXSEC: CSTP TLS1.3 inner record type %02x (KeyUpdate/PHA unsupported)\n"),
							     types[i]);
						return types[i] == 0x15 ? 0 : -EIO;
					}
				}
				g->tls_pl_n = nrecs;
				g->tls_pl_idx = 0;
				g->tls_rxoff += consumed;
				g->tls_rxlen -= consumed;
				if (!g->tls_rxlen)
					g->tls_rxoff = 0;
				if (dbg)
					fprintf(stderr, "[cstp] rx batch n=%d bytes=%zu\n",
						nrecs, off);
				goto have_plain;
			}
		}

		/* 一条完整记录都还没凑齐：继续读 */
		{
			int f = cstp_fill(g, vpninfo);

			if (f > 0) {
				if (dbg)
					fprintf(stderr, "[cstp] rx raw buf=%zu\n",
						g->tls_rxlen);
				continue;
			}
			if (f == -2)
				return 0;
			if (f < 0)
				return -EIO;
			if (dbg)
				fprintf(stderr, "[cstp] rx eagain (buf=%zu)\n",
					g->tls_rxlen);
			return -EAGAIN;
		}
	}
}

/* 把 outgoing_queue 里已经就绪的包继续拼进 dst，每帧填一个 iovec。
 * 注意：ocserv 的 parse_cstp_data() 有硬校验 buf_size == 8 + pktlen，
 * 也就是“一条 TLS 记录只能装一个 CSTP 帧”，所以这里绝不把多帧并进同一条
 * 记录，而是每帧一条记录、多条记录走同一次 SUBMIT_BATCH。
 * 队列 FIFO，顺序不变；放不下就 requeue 回去，不丢包。
 * 只在没开压缩时做（LZS 逐包压缩，输出还在共享的 deflate_pkt 里）。 */
static int cstp_gather(struct openconnect_info *vpninfo, uint8_t *dst,
		       size_t space, struct iovec *iov, int n)
{
	size_t used = 0;
	int start = n;

	while (n < ZXREC_MAX_BATCH) {
		struct pkt *p = dequeue_packet(&vpninfo->outgoing_queue);
		size_t need;

		if (!p)
			break;
		need = (size_t)p->len + 8;
		if (used + need > space) {
			requeue_packet(&vpninfo->outgoing_queue, p);
			break;
		}
		/* cstp.c 是“写之前”才填 CSTP 头，队列里的 hdr 还是空的 */
		p->cstp.hdr[0] = 'S';
		p->cstp.hdr[1] = 'T';
		p->cstp.hdr[2] = 'F';
		p->cstp.hdr[3] = 1;
		p->cstp.hdr[4] = (unsigned char)(p->len >> 8);
		p->cstp.hdr[5] = (unsigned char)p->len;
		p->cstp.hdr[6] = AC_PKT_DATA;
		p->cstp.hdr[7] = 0;
		memcpy(dst + used, p->cstp.hdr, need);
		iov[n].iov_base = dst + used;
		iov[n].iov_len = need;
		used += need;
		n++;
		free_pkt(vpninfo, p);
	}
	return n - start;
}

/* 已封装数据尽量写出去：1=写完，0=还没写完，-1=错误 */
static int cstp_drain(struct openconnect_info *vpninfo)
{
	struct zxsec_glue *g = &g_zx;
	int r = cstp_write_full(vpninfo->ssl_fd, g->tls_txbuf + g->tls_tx_off,
				g->tls_tx_len - g->tls_tx_off);

	if (r < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: CSTP write failed: %s\n"), strerror(errno));
		return -1;
	}
	g->tls_tx_off += (size_t)r;
	return g->tls_tx_off >= g->tls_tx_len;
}

static void cstp_tx_reset(void)
{
	struct zxsec_glue *g = &g_zx;

	g->tls_tx_len = g->tls_tx_off = g->tls_tx_done = 0;
	g->tls_tx_plen = 0;
	g->tls_tx_batch = 0;
}

/* 返回约定与 ssl_nonblock_write 一致：成功返回 len；0（-EAGAIN）= 暂时写不动
 * （记录已封装好，调用方用同一块数据重试时续写，不会重封、seq 不会错位）。
 * CSTP 的 ssl_fd 是非阻塞的，不能假设一次 write() 能写完；上层一次给的长度
 * 也可能超过单个记录的上限（HTTP POST 正文），按 16K 明文切块封装。 */
int zxsec_cstp_write(struct openconnect_info *vpninfo, void *buf, int len)
{
	struct zxsec_glue *g = &g_zx;
	int dbg = getenv("ZXSEC_DEBUG") != NULL;
	size_t done = 0;
	int r;

	if (len == 0)
		return 0;
	if (len < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("ZXSEC: CSTP write length %d out of range\n"), len);
		return -EIO;
	}

	if (g->tls_tx_len) {			/* 上一轮封好的还没写完 */
		if (g->tls_tx_plen != len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("ZXSEC: CSTP pending record %d vs new write %d\n"),
				     g->tls_tx_plen, len);
			return -EIO;
		}
		r = cstp_drain(vpninfo);
		if (r < 0)
			return -EIO;
		if (!r) {
			if (dbg)
				fprintf(stderr, "[cstp] tx partial %zu/%zu\n",
					g->tls_tx_off, g->tls_tx_len);
			return -EAGAIN;		/* 续写不重封 */
		}
		if (g->tls_tx_batch) {		/* 这一批就覆盖了整个调用 */
			cstp_tx_reset();
			return len;
		}
		done = g->tls_tx_done;
		g->tls_tx_len = g->tls_tx_off = 0;
	}

	while (done < (size_t)len) {
		struct iovec iov[ZXREC_MAX_BATCH];
		size_t round = (size_t)len - done;
		size_t total, outlen = 0;
		int nchunk = 0, is_frame;

		if (round > CSTP_AGGMAX)
			round = CSTP_AGGMAX;
		memcpy(g->tls_agg, (uint8_t *)buf + done, round);
		total = round;

		/* 调用者写的是 CSTP 帧（'S','T','F',1）：每帧一条记录 */
		is_frame = (round >= 8 && ((uint8_t *)buf)[done] == 'S' &&
			    ((uint8_t *)buf)[done + 1] == 'T' &&
			    ((uint8_t *)buf)[done + 2] == 'F' &&
			    ((uint8_t *)buf)[done + 3] == 1);

		if (is_frame) {
			iov[0].iov_base = g->tls_agg;
			iov[0].iov_len = round;
			nchunk = 1;
			/* 队列里还有就继续取，多条记录一次 ioctl 封出来。
			 * 服务端要求 record == 一个 CSTP 帧，所以不能并记录。 */
			if (done + round == (size_t)len && !vpninfo->cstp_compr &&
			    !getenv("ZXSEC_NO_TXAGG"))
				nchunk += cstp_gather(vpninfo, g->tls_agg + round,
						      CSTP_AGGMAX - round,
						      iov, nchunk);
		} else {
			/* HTTP CONNECT / 认证请求：按 16K 明文切块 */
			while (nchunk < ZXREC_MAX_BATCH &&
			       (size_t)nchunk * CSTP_MAX_PLAIN < total) {
				size_t off = (size_t)nchunk * CSTP_MAX_PLAIN;
				size_t cl = total - off;

				if (cl > CSTP_MAX_PLAIN)
					cl = CSTP_MAX_PLAIN;
				iov[nchunk].iov_base = g->tls_agg + off;
				iov[nchunk].iov_len = cl;
				nchunk++;
			}
		}

		r = zxsec_rl_seal(g->tls_rl, 0, iov, nchunk, g->tls_txbuf, CSTP_TXBUF,
				  &outlen, NULL, 0, NULL);
		if (r) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("ZXSEC: CSTP seal failed: %s\n"), strerror(-r));
			return -EIO;
		}
		g->tls_tx_len = outlen;
		g->tls_tx_off = 0;
		g->tls_tx_done = done + round;
		g->tls_tx_plen = len;
		g->tls_tx_batch = (g->tls_tx_done == (size_t)len);
		if (dbg)
			fprintf(stderr, "[cstp] tx seal plain=%zu records=%d out=%zu\n",
				total, nchunk, outlen);

		r = cstp_drain(vpninfo);
		if (r < 0)
			return -EIO;
		if (!r)
			return -EAGAIN;
		if (g->tls_tx_batch) {
			cstp_tx_reset();
			return len;
		}
		done = g->tls_tx_done;
		g->tls_tx_len = g->tls_tx_off = 0;
	}

	cstp_tx_reset();
	return len;
}

/* -------------------- 阻塞语义包装 -------------------- */

/*
 * ssl_nonblock_read/write 需要“WANT_READ/WANT_WRITE → 0”的语义，保持非阻塞；
 * 而 openconnect_openssl_read/write/gets 这几个包装是给 HTTP 层用的，必须
 * 阻塞到有结果（HTTP CONNECT 的请求和响应都在这里过），所以在这里等 fd。
 */
static int cstp_wait_fd(int fd, short ev)
{
	struct pollfd pfd;
	int r;

	pfd.fd = fd;
	pfd.events = ev;
	pfd.revents = 0;
	do {
		r = poll(&pfd, 1, -1);
	} while (r < 0 && errno == EINTR);
	return r < 0 ? -1 : 0;
}

int zxsec_cstp_read_wait(struct openconnect_info *vpninfo, void *buf, int maxlen)
{
	int r;

	while ((r = zxsec_cstp_read(vpninfo, buf, maxlen)) == -EAGAIN)
		if (cstp_wait_fd(vpninfo->ssl_fd, POLLIN))
			return -EIO;
	return r;
}

int zxsec_cstp_write_wait(struct openconnect_info *vpninfo, void *buf, int len)
{
	int r;

	while ((r = zxsec_cstp_write(vpninfo, buf, len)) == -EAGAIN)
		if (cstp_wait_fd(vpninfo->ssl_fd, POLLOUT))
			return -EIO;
	return r;
}
