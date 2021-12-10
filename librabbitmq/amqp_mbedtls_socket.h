/** \file */
/**
 * A MBEDTLS socket connection.
 */

#ifndef AMQP_MBEDTLS_SOCKET_H
#define AMQP_MBEDTLS_SOCKET_H

 
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"
//#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/base64.h"

#include  <rabbitmq-c/amqp.h>

AMQP_BEGIN_DECLS

/**
 * Create a new MBEDTLS socket.
 *
 * Call amqp_connection_close() to release socket resources.
 *
 * \return A new socket object or NULL if an error occurred.
 *
 * \since v0.4.0 
 */
AMQP_EXPORT
amqp_socket_t *AMQP_CALL amqp_mbedtls_socket_new(amqp_connection_state_t state);

/**
 * Assign an open file descriptor to a socket object.
 *
 * This function must not be used in conjunction with amqp_socket_open(), i.e.
 * the socket connection should already be open(2) when this function is
 * called.
 *
 * \param [in,out] self A mbedtls socket object.
 * \param [in] sockfd An open socket descriptor.
 *
 * \since v0.4.0
 */
AMQP_EXPORT
void AMQP_CALL amqp_mbedtls_socket_set_sockfd(amqp_socket_t *self, int sockfd);

/**
 * Get the internal MBEDTLS context.  
 *
 * \param [in,out] self An MBEDTLS socket object.
 *
 * \return A pointer to the internal MBEDTLS context.  
 *  
 */
AMQP_EXPORT
void *AMQP_CALL amqp_mbedtls_socket_get_context(amqp_socket_t *base);
/**
 * set flag to Enable or disable peer verification.
 * If peer verification is enabled then the common name in the server
 * certificate must match the server name in amqp_mbedtls_ssl_socket_open().
 *  Peer verification is enabled by default.
 *
 */
AMQP_EXPORT
void AMQP_CALL amqp_mbedtls_set_auth_mode(const char *key);
/**
 * Set the CA certificate file path.
 *
 */
AMQP_EXPORT
void AMQP_CALL amqp_mbedtls_set_cacert_file(const char *cacert);
/**
 * Set the client certificate file and key file path.
 *
 */
AMQP_EXPORT
void AMQP_CALL amqp_mbedtls_set_crt_file(const char *crtcert, const char *crtkey);

AMQP_END_DECLS

#endif /* AMQP_MBEDTLS_SOCKET_H */
