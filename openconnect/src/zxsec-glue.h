/*
 * zxsec-glue.h - openconnect 与 zxsec-record codec 的粘合层接口
 */
#ifndef __OPENCONNECT_ZXSEC_GLUE_H
#define __OPENCONNECT_ZXSEC_GLUE_H

#include <sys/uio.h>

struct openconnect_info;

/* GnuTLS 动态库通过弱符号调用它们；OpenSSL 构建里只是未使用的声明。 */
void oc_zxsec_gnutls_on_keys(void *session, int is_dtls, int epoch,
			     int is_write, const unsigned char *key,
			     size_t key_len, const unsigned char *iv,
			     size_t iv_len, int cipher_id, int version_id);
void oc_zxsec_gnutls13_on_keys(void *session, int is_write,
			       const unsigned char *key, unsigned key_len,
			       const unsigned char *iv, unsigned iv_len,
			       int cipher_id, int is_app);

int  zxsec_glue_available(void);
void zxsec_glue_dtls_init(struct openconnect_info *vpninfo);
void zxsec_glue_dtls_check(struct openconnect_info *vpninfo);
void zxsec_glue_dtls_disable(void);
int  zxsec_dtls_read(struct openconnect_info *vpninfo, unsigned char *buf,
		     int maxlen);
int  zxsec_dtls_write(struct openconnect_info *vpninfo, void *buf, int len);
int  zxsec_dtls_read_wait(struct openconnect_info *vpninfo, void *buf, int len,
			  unsigned ms);
int  zxsec_dtls_write_wait(struct openconnect_info *vpninfo, void *buf, int len);
int  zxsec_dtls_tx_batch(struct openconnect_info *vpninfo);

/*
 * CSTP/TCP 通道：TLS 握手一结束（openssl.c / gnutls.c 的 connect 尾部）
 * 就 bind。bind 把 TLS 库钩子在握手阶段暂存的 key/salt 装进独立的 TLS
 * 记录层，并做 gate 检查（TLS1.2 + AES-GCM）。通过后
 * ssl_read/ssl_write/ssl_gets 以及 nonblock 版本的调用全部转到这里，
 * 从认证 POST、HTTP CONNECT 直到隧道数据都由自管记录层加解密——关键是
 * write seq 必须按 TLS 库当前值对齐，晚绑定会漏掉前面已经用掉的 seq。
 * 连接关闭（openconnect_close_https）时调用 unbind 清状态。
 */
void zxsec_glue_tls_bind(struct openconnect_info *vpninfo);
void zxsec_glue_tls_unbind(struct openconnect_info *vpninfo);
int  zxsec_cstp_active(struct openconnect_info *vpninfo);
int  zxsec_cstp_read(struct openconnect_info *vpninfo, void *buf, int maxlen);
int  zxsec_cstp_write(struct openconnect_info *vpninfo, void *buf, int len);
int  zxsec_cstp_read_wait(struct openconnect_info *vpninfo, void *buf, int maxlen);
int  zxsec_cstp_write_wait(struct openconnect_info *vpninfo, void *buf, int len);

#endif
