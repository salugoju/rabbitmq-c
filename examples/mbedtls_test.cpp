#include "winsock2.h"
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include <iostream> 
#include <string> 
 
#include <amqp_ssl_socket.h>
#include <amqp_tcp_socket.h>
#include <stdio.h> 
#include "amqp_mbedtls_socket.h"
#include <amqp.h> 
 

using namespace std;
 

#define AMQP_PROPS_FLAGS AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG | AMQP_BASIC_TYPE_FLAG


std::string hostname = "localhost";
int port = 5671;
 
amqp_socket_t *connSocket;
amqp_connection_state_t conn;
amqp_channel_t channel=2;
std::string  bindingKey = "testmbedtls";
amqp_rpc_reply_t status;
amqp_bytes_t queue; 
std::string exchange = "MessageBus"; 
std::string vhost;
int heartbeat=60;
bool recvconnected = false;
 

void close_recvconnection()
{
	if (recvconnected)
	{
		recvconnected = false;

		try
		{
			amqp_rpc_reply_t status = amqp_channel_close(conn, channel, AMQP_REPLY_SUCCESS);
			if (status.reply_type != AMQP_RESPONSE_NORMAL)
			{
				printf(" - amqp_channel_close  ");
			}
			status = amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
			if (status.reply_type != AMQP_RESPONSE_NORMAL)
			{
				printf("   amqp_connection_close  ");
			}
			if (AMQP_STATUS_OK == amqp_destroy_connection(conn))
			{
				printf(" amqp_destroy_connection- Disconnect successful\n");
			}
			conn = NULL;
			connSocket = NULL;
		}
		catch (int e)
		{
			printf(" Failed due to Exception : Exception Nr. %d \n", e);
		}
	}
}
bool recvinit()
{
	bool ret = false;
	try
	{
		conn = amqp_new_connection();
		if (conn != NULL)
		{
//#if def10
			connSocket =amqp_mbedtls_socket_new(conn);// amqp_ssl_socket_new(conn);// // amqp_tcp_socket_new(conn);
				/**/
			if (connSocket != NULL)
			{

				amqp_mbedtls_set_auth_mode("optional");
				amqp_mbedtls_set_cacert_file("c:\\tlsgen\\certificate\\ca_certificate.pem");
				amqp_mbedtls_set_crt_file("c:\\tlsgen\\certificate\\client_certificate.pem", "c:\\tlsgen\\certificate\\client_key.pem");
//#endif
#if def12
				connSocket = amqp_ssl_socket_new(conn);// //amqp_mbedtls_socket_new(conn);// amqp_tcp_socket_new(conn);
			/**/
				if (connSocket != NULL)
				{

				amqp_ssl_socket_set_verify_peer(connSocket, 0);
				amqp_ssl_socket_set_verify_hostname(connSocket, 0);
				amqp_ssl_socket_set_cacert(connSocket, "c:\\tlsgen\\certificate\\ca_certificate.pem");
				amqp_set_ssl_engine("engine");
				amqp_ssl_socket_set_verify_peer(connSocket, 1);
				amqp_ssl_socket_set_verify_hostname(connSocket, 1);
				amqp_ssl_socket_set_key(connSocket, "c:\\tlsgen\\certificate\\client_certificate.pem", "c:\\tlsgen\\certificate\\client_key.pem");
 
#endif

				struct timeval timeout;
				timeout.tv_sec = 5;
				timeout.tv_usec = 0;

				if (amqp_socket_open_noblock(connSocket, hostname.c_str(), port, &timeout) == AMQP_STATUS_OK)
				{
					amqp_table_t client_capabilities_table;
					amqp_table_entry_t client_capabilities[5];
					amqp_table_entry_t tempret;
					tempret.key = amqp_cstring_bytes("basic.nack");
					tempret.value.kind = AMQP_FIELD_KIND_BOOLEAN;
					tempret.value.value.boolean = 1;
					client_capabilities[0] = tempret;
					tempret.key = amqp_cstring_bytes("connection.blocked");
					client_capabilities[1] = tempret;
					tempret.key = amqp_cstring_bytes("consumer_cancel_notify");
					client_capabilities[2] = tempret;
					tempret.key = amqp_cstring_bytes("exchange_exchange_bindings");
					client_capabilities[3] = tempret;
					tempret.key = amqp_cstring_bytes("publisher_confirms");
					client_capabilities[4] = tempret;
					client_capabilities_table.entries = client_capabilities;
					client_capabilities_table.num_entries =
						sizeof(client_capabilities) / sizeof(amqp_table_entry_t);

					///NOTE: rabbitmq - c does not support heartbeats, your best bet is not to implement this.
					amqp_rpc_reply_t status = amqp_login_with_properties(conn, AMQP_DEFAULT_VHOST, AMQP_DEFAULT_MAX_CHANNELS, AMQP_DEFAULT_FRAME_SIZE, heartbeat, &client_capabilities_table, AMQP_SASL_METHOD_PLAIN, "admin", "admin");

					if (status.reply_type == AMQP_RESPONSE_NORMAL)
					{
						amqp_channel_open(conn, channel);
						status = amqp_get_rpc_reply(conn);
						if (status.reply_type == AMQP_RESPONSE_NORMAL)
						{
							printf(" initialize connection successful \n");
							ret = true;
						}
						else
						{
							printf("FAILED: Opening channel");
							close_recvconnection();
						}
					}
					else
					{
						printf("FAILED:rx amqp_login_with_properties");
						close_recvconnection();
					}
				}
				else
				{
					fprintf(stderr, "FAILED:rx amqp_socket_open_noblock");
					close_recvconnection();
				}
			}
			else
			{
				printf("FAILED:rx connSocket null");
				close_recvconnection();
			}
		}
		else
		{
			close_recvconnection();
			printf("FAILED: conn null");
		}
	}
	catch (int e)
	{
		printf("  Failed due to Exception- Exception Nr. %d \n", e);
		close_recvconnection();
	}
	if (!ret)
	{
		close_recvconnection();
	}
	return ret;

}


int main(void)
{
	
	printf("begin init \n");

	if (recvinit())
	{
		recvconnected = true;
	}
	printf("end init \n");

}