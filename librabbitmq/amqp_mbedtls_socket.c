/*  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _MSC_VER
//#define _CRT_SECURE_NO_WARNINGS
#endif
#include "amqp_mbedtls_socket.h"
#include "mbedtls/x509_crt.h"
#include "amqp_private.h"
#include "amqp_socket.h"
#include "amqp_time.h"
#include "threads.h"
#include "mbedtls\ssl.h"
#include "mbedtls\ctr_drbg.h"
#include "mbedtls\net_sockets.h"
#include "mbedtls\entropy.h"
#include "mbedtls\x509.h"
#include "mbedtls\timing.h"
//#include "amqp_mbedtls_rng.h"

/* Size of memory to be allocated for the heap, when using the library's memory
 * management and MBEDTLS_MEMORY_BUFFER_ALLOC_C is enabled. */

#define MAX_REQUEST_SIZE		20000 
#define DFL_SERVER_NAME         "localhost"
#define DFL_SERVER_ADDR         NULL 
#define DFL_SERVER_PORT         "5671"
#define DFL_DEBUG_LEVEL         2
#define DFL_READ_TIMEOUT        0
#define DFL_MAX_RESEND          0
#define DFL_CA_FILE             ""
#define DFL_CRT_FILE            ""
#define DFL_KEY_FILE            ""
#define DFL_AUTH_MODE           -1
#define DFL_MFL_CODE            MBEDTLS_SSL_MAX_FRAG_LEN_NONE
#define DFL_TICKETS             MBEDTLS_SSL_SESSION_TICKETS_ENABLED
#define DFL_TRANSPORT           MBEDTLS_SSL_TRANSPORT_STREAM 
#define DFL_CONTEXT_FILE        ""
#define DFL_EXTENDED_MS_ENFORCE -1
#define DFL_CA_CALLBACK         0
#define DFL_SKIP_CLOSE_NOTIFY   0
  
/*
 * global options
 */
typedef struct 
{
	const char *server_name;    /* hostname of the server (client only)     */
	const char *server_addr;    /* address of the server (client only)      */
	const char *server_port;    /* port on which the ssl service runs       */
	int debug_level;            /* level of debugging                       */
	int nbio;                   /* should I/O be blocking?                  */		 
	const char *ca_file;        /* the file with the CA certificate(s)      */	
	const char *crt_file;       /* the file with the client certificate     */
	const char *key_file;       /* the file with the client key             */  
	int auth_mode;              /* verify mode for connection               */
	unsigned char mfl_code;     /* code for maximum fragment length         */	   
	int cid_enabled;            /* whether to use the CID extension or not  */ 
	const char *context_file;   /* the file to write a serialized connection
								 * in the form of base64 code (serialize
								 * option must be set)                      */  
	int skip_close_notify;      /* skip sending the close_notify alert      */ 

} mbedtls_options;
static mbedtls_options conf_opt; 
typedef enum amqp_mbedtls_connection_state_enum_ {
	NO_STATE = 0,
	INIT_STATE0,
	INIT_STATE,
	CONNECTED_STATE,
	DISCONNECTED_STATE,
	ERROR_STATE
} amqp_mbedtls_connection_state_enum;
amqp_mbedtls_connection_state_enum mbedtls_state = NO_STATE;
typedef struct
{
	mbedtls_ssl_context *ssl;
	mbedtls_net_context *net;
} io_ctx_t;
struct amqp_mbedtls_socket_t 
{
	const struct amqp_socket_class_t *klass;
	mbedtls_ssl_context ctx;	
	int sockfd;
	int internal_error;	
	mbedtls_net_context server_fd;
	io_ctx_t io_ctx;
	unsigned char buf[MAX_REQUEST_SIZE + 1];
	const char *pers;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
 
	mbedtls_ssl_config conf;
	
	unsigned char *session_data;
	size_t session_data_len;
#if defined(MBEDTLS_TIMING_C)
	mbedtls_timing_delay_context timer;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_profile crt_profile_for_test;
	uint32_t flags;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt clicert;
	mbedtls_pk_context pkey;
#endif  /* MBEDTLS_X509_CRT_PARSE_C */
};

/* sets up the default options for the mbedtls on TCP */
void amqp_mbedtls_socket_set_default_options()
{
	conf_opt.server_name = DFL_SERVER_NAME;
	conf_opt.server_addr = DFL_SERVER_ADDR;
	conf_opt.server_port = DFL_SERVER_PORT;
	conf_opt.debug_level = DFL_DEBUG_LEVEL; 
 	conf_opt.ca_file = DFL_CA_FILE;	
	conf_opt.crt_file = DFL_CRT_FILE;
	conf_opt.key_file = DFL_KEY_FILE;	 
	conf_opt.auth_mode = DFL_AUTH_MODE;
	conf_opt.mfl_code = DFL_MFL_CODE; 
	conf_opt.context_file = DFL_CONTEXT_FILE; 
	conf_opt.skip_close_notify = DFL_SKIP_CLOSE_NOTIFY; 
	mbedtls_state = INIT_STATE;
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static unsigned char peer_crt_info[1024];
/*
 * Enabled if debug_level > 1 in code below
 */
static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
	char buf[1024];
	((void)data);

	mbedtls_printf("\nVerify requested for (Depth %d):\n", depth);

	mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
	if (depth == 0)
	{
		memcpy(peer_crt_info, buf, sizeof(buf));
	}

	if (conf_opt.debug_level == 0)
	{
		return(0);
	}

	mbedtls_printf("%s", buf);

	if ((*flags) == 0)
	{
		mbedtls_printf("  This certificate has no flags\n");
	}
	else
	{
		mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", *flags);
		mbedtls_printf("%s\n", buf);
	}
	return(0);
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	((void)level); fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str); fflush((FILE *)ctx);
}
 
#if !defined(MBEDTLS_TEST_USE_PSA_CRYPTO_RNG)
static int dummy_entropy(void *data, unsigned char *output, size_t len)
{
	size_t i;
	int ret;
	(void)data;

	ret = mbedtls_entropy_func(data, output, len);
	for (i = 0; i < len; i++)
	{
		//replace result with pseudo random
		output[i] = (unsigned char)rand();
	}
	return(ret);
}
#endif
 

/****TBD ****/
int delayed_recv(void *ctx, unsigned char *buf, size_t len)
{
	static int first_try = 1;
	int ret;

	if (first_try)
	{
		first_try = 0;
		return(MBEDTLS_ERR_SSL_WANT_READ);
	}

	ret = mbedtls_net_recv(ctx, buf, len);
	if (ret != MBEDTLS_ERR_SSL_WANT_READ)
		first_try = 1; /* Next call will be a new operation */
	return(ret);
}

int delayed_send(void *ctx, const unsigned char *buf, size_t len)
{
	static int first_try = 1;
	int ret;

	if (first_try)
	{
		first_try = 0;
		return(MBEDTLS_ERR_SSL_WANT_WRITE);
	}

	ret = mbedtls_net_send(ctx, buf, len);
	if (ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		first_try = 1; /* Next call will be a new operation */
	return(ret);
}

int send_cb(void *ctx, unsigned char const *buf, size_t len)
{
	io_ctx_t *io_ctx = (io_ctx_t*)ctx;
	return(mbedtls_net_send(io_ctx->net, buf, len));
}
int recv_timeout_cb(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
	io_ctx_t *io_ctx = (io_ctx_t*)ctx;
	int ret;
	size_t recv_len;

	ret = mbedtls_net_recv_timeout(io_ctx->net, buf, len, timeout);
	if (ret < 0)
	{
		return(ret);
	}
	recv_len = (size_t)ret;

	return((int)recv_len);
}
int recv_cb(void *ctx, unsigned char *buf, size_t len)
{
	io_ctx_t *io_ctx = (io_ctx_t*)ctx;
	size_t recv_len;
	int ret;

	ret = mbedtls_net_recv(io_ctx->net, buf, len);
	if (ret < 0)
	{
		return(ret);
	}
	recv_len = (size_t)ret;
	return((int)recv_len);
}


/*******SSL*******/
static ssize_t amqp_mbedtls_ssl_socket_send(void *base, const void *buf, size_t len,AMQP_UNUSED int flags) 
{
		struct amqp_mbedtls_socket_t *self;
	self = (struct amqp_mbedtls_socket_t *)base;
	 
	int ret = -1;
	int written = 0;
	int frags = 0;
	do
	{
		while ((ret = mbedtls_ssl_write(&self->ctx, self->buf + written,len - written)) < 0)
		{
			if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
				ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
				ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
			{
				mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned -0x%x\n\n",
					(unsigned int)-ret);
				return AMQP_STATUS_MBEDTLS_ERROR;
			}
		}
		frags++;
		written += ret;
	} while (written < len);
	self->buf[written] = '\0';
	mbedtls_printf(" %d bytes written in %d fragments\n\n%s\n", written, frags, (char *)buf);
	return written;
}

static ssize_t amqp_mbedtls_ssl_socket_recv(void *base, void *buf, size_t len,AMQP_UNUSED int flags)
{
	struct amqp_mbedtls_socket_t *self;
	self = (struct amqp_mbedtls_socket_t *)base;
	ssize_t ret;

	int lret = -1;
	/*if (-1 == self->sockfd) 
	{
		return AMQP_STATUS_SOCKET_CLOSED;
	}*/
	len = sizeof(buf) - 1;
	memset(buf, 0, sizeof(buf));
	ret = mbedtls_ssl_read(&self->ctx, buf, len);	

	if (ret <= 0)
	{
		switch (ret)
		{
		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			mbedtls_printf(" connection was closed gracefully\n");
		 
			break; 

		case 0:
		case MBEDTLS_ERR_NET_CONN_RESET:
			mbedtls_printf(" connection was reset by peer\n");
			 
			break;

		default:
			mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n",
				(unsigned int)-ret);
			break;
		}
 
		return AMQP_STATUS_MBEDTLS_ERROR;
	}
	 
	len = ret;
	self->buf[len] = '\0';
	mbedtls_printf(" %d bytes read\n\n%s", len, (char *)self->buf[len]);
	 
	return ret;
}

static int amqp_mbedtls_ssl_socket_open(void *base, const char *host, int port, const struct timeval *timeout)
{
	struct amqp_mbedtls_socket_t *self;
	self = (struct amqp_mbedtls_socket_t *)base;
	int lret = -1;
	int ret = -1;
	(void)sprintf(conf_opt.server_port, "%d", port);
	conf_opt.server_addr = host;	 

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	/*
	 * 1.1. Load the trusted CA
	 */
	mbedtls_printf("  . Loading the CA root certificate ...");
	fflush(stdout);
#if defined(MBEDTLS_FS_IO)
	ret = -1;
	if (strlen(conf_opt.ca_file))
	{
		ret = mbedtls_x509_crt_parse_file(&self->cacert, conf_opt.ca_file);
	}
	if (ret != 0)
	{
		mbedtls_printf(" failed\n  !  Load the trusted CA: mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int)-ret);
		return lret;
	}

	/*
	 * 1.2. Load own certificate and private key
	 *
	 * (can be skipped if client authentication is not required)
	 */
	mbedtls_printf("  . Loading the client cert. and key...");
	fflush(stdout);
	ret = -1;
	if (strlen(conf_opt.crt_file))
	{
		ret = mbedtls_x509_crt_parse_file(&self->clicert, conf_opt.crt_file);
	}
	if (ret != 0)	
	{
		mbedtls_printf(" failed\n  ! Load own certificate and private key: mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int)-ret);
		return lret;
	}
	ret = -1;
	if (strlen(conf_opt.key_file))
	{
		ret = mbedtls_pk_parse_keyfile(&self->pkey, conf_opt.key_file,0);
	}
	if (ret != 0)
	{
		mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned -0x%x\n\n", (unsigned int)-ret);
		return lret;
	}
#endif
#endif
	/*
	 * 2. Start the connection
	 */
	if (conf_opt.server_addr == NULL)
		conf_opt.server_addr = conf_opt.server_name;
	 
	if ((ret = mbedtls_net_connect(&self->server_fd, conf_opt.server_addr, conf_opt.server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_net_connect returned -0x%x\n\n", (unsigned int)-ret);
		return lret;
	}
	ret = -1;
	ret = mbedtls_net_set_block(&self->server_fd);
	
	if (ret != 0)
	{
		mbedtls_printf(" failed\n  !   Set the socket blocking or non-blocking -0x%x\n\n", (unsigned int)-ret);
		return lret;
	}
	/*
	 * 3. Setup stuff
	 */
	mbedtls_printf("  . Setting up the SSL/TLS structure...");
	fflush(stdout);
	ret = -1;
	if ((ret = mbedtls_ssl_config_defaults(&self->conf, MBEDTLS_SSL_IS_CLIENT,
		DFL_TRANSPORT, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", (unsigned int)-ret);
		return lret;
	}
	
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_ssl_conf_verify(&self->conf, my_verify, NULL);
	memset(peer_crt_info, 0, sizeof(peer_crt_info));
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	if (conf_opt.auth_mode != DFL_AUTH_MODE)
	{
		mbedtls_ssl_conf_authmode(&self->conf, conf_opt.auth_mode);
	}

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
	if ((ret = mbedtls_ssl_conf_max_frag_len(&self->conf, conf_opt.mfl_code)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_max_frag_len returned %d\n\n", ret);
		return lret;
	}
#endif

	mbedtls_ssl_conf_rng(&self->conf, mbedtls_ctr_drbg_random, &self->ctr_drbg);
	mbedtls_ssl_conf_dbg(&self->conf, my_debug, stdout);
	mbedtls_ssl_conf_read_timeout(&self->conf, DFL_READ_TIMEOUT);

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
	mbedtls_ssl_conf_session_tickets(&self->conf, DFL_TICKETS);
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
//	mbedtls_ssl_conf_renegotiation(&self->conf, conf_opt.renegotiation); //disabled considering security issues
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	if (strcmp(conf_opt.ca_file, "none") != 0)
	{
		mbedtls_ssl_conf_ca_chain(&self->conf, &self->cacert, NULL);
	}
	if (strcmp(conf_opt.crt_file, "none") != 0 &&
		strcmp(conf_opt.key_file, "none") != 0)
	{
		if ((ret = mbedtls_ssl_conf_own_cert(&self->conf, &self->clicert, &self->pkey)) != 0)
		{
			mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
			return lret;
		}
	}
#endif  /* MBEDTLS_X509_CRT_PARSE_C */
	if ((ret = mbedtls_ssl_setup(&self->ctx, &self->conf)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", (unsigned int)-ret);
		return lret;
	}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	if ((ret = mbedtls_ssl_set_hostname(&self->ctx, conf_opt.server_name)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		return lret;
	}
#endif
	self->io_ctx.ssl = &self->ctx;
	self->io_ctx.net = &self->server_fd;
//	mbedtls_ssl_set_bio(&self->ctx, &self->io_ctx, send_cb, recv_cb, conf_opt.nbio == 0 ? recv_timeout_cb : NULL);
	mbedtls_ssl_set_bio(&self->ctx, &self->io_ctx, send_cb, recv_cb, NULL);
#if defined(MBEDTLS_TIMING_C)
	mbedtls_ssl_set_timer_cb(&self->ctx, &self->timer, mbedtls_timing_set_delay,
		mbedtls_timing_get_delay);
#endif
	/*
	* 4. Handshake
	*/
	mbedtls_printf("  . Performing the SSL/TLS handshake...");
	fflush(stdout);
	 ret = -1;
	 mbedtls_ssl_context *ssl = &self->ctx;
	while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
			ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
			ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
		{
			mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", (unsigned int)-ret);
			if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
				mbedtls_printf(
					"    Unable to verify the server's certificate. "
					"Either it is invalid,\n"
					"    or you didn't set ca_file to an appropriate value.\n"
					"    Alternatively, you may want to use "
					"auth_mode=optional for testing purposes.\n");
			mbedtls_printf("\n");
			return lret;
		}
	}

	mbedtls_printf(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
		mbedtls_ssl_get_version(&self->ctx),
		mbedtls_ssl_get_ciphersuite(&self->ctx));

	if ((ret = mbedtls_ssl_get_record_expansion(&self->ctx)) >= 0)
		mbedtls_printf("    [ Record expansion is %d ]\n", ret);
	else
		mbedtls_printf("    [ Record expansion is unknown (compression) ]\n");

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
	mbedtls_printf("    [ Maximum incoming record payload length is %u ]\n",
		(unsigned int)mbedtls_ssl_get_input_max_frag_len(&self->ctx));
	mbedtls_printf("    [ Maximum outgoing record payload length is %u ]\n",
		(unsigned int)mbedtls_ssl_get_output_max_frag_len(&self->ctx));
#endif
	#if defined(MBEDTLS_X509_CRT_PARSE_C)
	/*
	 * 5. Verify the server certificate
	 */
	mbedtls_printf("  . Verifying peer X.509 certificate...");

	if ((self->flags = mbedtls_ssl_get_verify_result(&self->ctx)) != 0)
	{
		char vrfy_buf[512];
		mbedtls_printf(" failed\n");

		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf),"  ! ", self->flags);

		mbedtls_printf("%s\n", vrfy_buf);
		return lret;
	}
	else
	{
		ret = 0;
		mbedtls_printf(" ok\n");
	}

#if !defined(MBEDTLS_X509_REMOVE_INFO)
	mbedtls_printf("  . Peer certificate information    ...\n");
	mbedtls_printf("%s\n", peer_crt_info);
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	if (ret == 0)
	{
		lret = 0;
		mbedtls_state = CONNECTED_STATE;
		mbedtls_printf(" ok\n");
	}
	else
	{
		mbedtls_printf(" failed\n  !Returned -0x%x\n\n", (unsigned int)-ret);
	}
	return lret;
}

static int amqp_mbedtls_ssl_socket_close(void *base, amqp_socket_close_enum force) 
{
	struct amqp_mbedtls_socket_t *self;
	self = (struct amqp_mbedtls_socket_t *)base;
	int lret = -1;
	int ret = -1;

	mbedtls_printf("  . Closing the connection...");
	fflush(stdout);

	/*
	 * Most of the time sending a close_notify before closing is the right
	 * thing to do. However, when the server already knows how many messages
	 * are expected and closes the connection by itself, this alert becomes
	 * redundant. Sometimes with DTLS this redundancy becomes a problem by
	 * leading to a race condition where the server might close the connection
	 * before seeing the alert, and since UDP is connection-less when the
	 * alert arrives it will be seen as a new connection, which will fail as
	 * the alert is clearly not a valid ClientHello. This may cause spurious
	 * failures in tests that use DTLS and resumption with ssl_server2 in
	 * ssl-opt.sh, avoided by enabling skip_close_notify client-side.
	 */
	if (conf_opt.skip_close_notify == 0)
	{
		/* No error checking, the connection might be closed already */
		do ret = mbedtls_ssl_close_notify(&self->ctx);
		while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
		ret = 0;
	}
	mbedtls_printf(" done\n");
	return ret;
}

static int amqp_mbedtls_ssl_socket_get_sockfd(void *base) 
{
	struct amqp_mbedtls_socket_t *self = (struct amqp_mbedtls_socket_t *)base;
	return self->sockfd;
}

static void amqp_mbedtls_ssl_socket_delete(void *base) 
{
	struct amqp_mbedtls_socket_t *self;
	self = (struct amqp_mbedtls_socket_t *)base;
	int ret = -1;
	int query_config_ret = 0;

	mbedtls_net_free(&self->server_fd);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_free(&self->clicert);
	mbedtls_x509_crt_free(&self->cacert);
	mbedtls_pk_free(&self->pkey);
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	
	mbedtls_ssl_free(&self->ctx);
	mbedtls_ssl_config_free(&self->conf);

	mbedtls_ctr_drbg_free(&self->ctr_drbg);
	mbedtls_entropy_free(&self->entropy);
 
	if (self->session_data != NULL)
		mbedtls_platform_zeroize(self->session_data, self->session_data_len);
	mbedtls_free(self->session_data);
	mbedtls_exit(ret);	
}

static const struct amqp_socket_class_t amqp_mbedtls_socket_class = {
	amqp_mbedtls_ssl_socket_send,       /* send */
	amqp_mbedtls_ssl_socket_recv,       /* recv */
	amqp_mbedtls_ssl_socket_open,       /* open */
	amqp_mbedtls_ssl_socket_close,      /* close */
	amqp_mbedtls_ssl_socket_get_sockfd, /* get_sockfd */
	amqp_mbedtls_ssl_socket_delete      /* delete */
};
amqp_socket_t *amqp_mbedtls_socket_new(amqp_connection_state_t state) 
{
	struct amqp_mbedtls_socket_t *self = calloc(1, sizeof(*self));
	int status;
	if (!self) 
	{
		return NULL;
	}
	self->sockfd = -1;
	self->klass = &amqp_mbedtls_socket_class;
	self->crt_profile_for_test = mbedtls_x509_crt_profile_default;
	self->pers = "rmq_mbedtls_client";
 	/*
	* Make sure memory references are valid.
	*/
	mbedtls_net_init(&self->server_fd);
	mbedtls_ssl_init(&self->ctx);
	mbedtls_ssl_config_init(&self->conf);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_init(&self->cacert);
	mbedtls_x509_crt_init(&self->clicert);
	mbedtls_pk_init(&self->pkey);
#endif
	mbedtls_ctr_drbg_init(&self->ctr_drbg);
	mbedtls_entropy_init(&self->entropy);
	 
	int ret;
 
	// Init RNG
	if (0 != (ret = mbedtls_ctr_drbg_seed(&self->ctr_drbg, mbedtls_entropy_func, &self->entropy, self->pers, strlen(self->pers)))) // Note: Using instance name for additional entropy.
	{
		mbedtls_printf("ERROR mbedtls_ctr_drbg_seed() failed. ret= %d",  ret);
		return NULL;
	}

	amqp_mbedtls_socket_set_default_options();
#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(conf_opt.debug_level);
#endif
	mbedtls_state = INIT_STATE0;
	//set the socket object
	amqp_set_socket(state, (amqp_socket_t *)self);
	return (amqp_socket_t *)self;
}
void amqp_mbedtls_socket_set_sockfd(amqp_socket_t *base, int sockfd)
{
	struct amqp_mbedtls_socket_t *self;
	if (base->klass != &amqp_mbedtls_socket_class) {
		amqp_abort("<%p> is not of type amqp_tcp_socket_t", base);
	}
	self = (struct amqp_mbedtls_socket_t *)base; 
	self->sockfd = sockfd;
}
/*
 *  returns the tls context.
 */
void *amqp_mbedtls_socket_get_context(amqp_socket_t *base) 
{
	if (base->klass != &amqp_mbedtls_socket_class) 
	{
		amqp_abort("<%p> is not of type amqp_ssl_socket_t", base);
	}
	return &(((struct amqp_mbedtls_socket_t *)base)->ctx);
}
/* prints the X.509 certificate from the crt Container .*/
int amqp_mbedtls_print_Certificate(mbedtls_x509_crt crt)
{
	int ret = -1;
	char buf[1024];
	mbedtls_x509_crt *cur = &crt;
	mbedtls_printf("  . Peer certificate information    ...\n");
	ret = mbedtls_x509_crt_info((char *)buf, sizeof(buf) - 1, "      ",cur);
	if (ret == -1)
	{
		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_info returned %d\n\n", ret);
		mbedtls_x509_crt_free(&crt); 
	}
	mbedtls_printf("%s\n", buf);
	return ret;
}

void amqp_mbedtls_set_cacert_file(const char *cacert)
{
	conf_opt.ca_file = cacert;
}
void amqp_mbedtls_set_crt_file(const char *crtcert, const char *crtkey )
{	 
	conf_opt.crt_file = crtcert;
	conf_opt.key_file = crtkey;
}
void amqp_mbedtls_set_auth_mode(const char *key)
{
	conf_opt.auth_mode = MBEDTLS_SSL_VERIFY_NONE;
	if (strcmp(key, "none") == 0)
		conf_opt.auth_mode = MBEDTLS_SSL_VERIFY_NONE;
	else if (strcmp(key, "optional") == 0)
		conf_opt.auth_mode = MBEDTLS_SSL_VERIFY_OPTIONAL;
	else if (strcmp(key, "required") == 0)
		conf_opt.auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;	
}

 