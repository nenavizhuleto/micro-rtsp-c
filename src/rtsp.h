#ifndef __RTSP__H
#define __RTSP__H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "linked_list.h"

#define RTSP_BUFFER_SIZE	10000
#define RTSP_PARAM_MAX_SIZE	200
#define RTSP_HOSTNAME_MAX_SIZE	256

typedef struct {
	char *host;
	char *presentation;
	char *stream;

	int rtp_sock;
	int rtcp_sock;

	uint16_t rtp_port;
	uint16_t rtcp_port;

	uint32_t cseq;
	uint32_t timestamp;

	int send_idx;

	llist_item_t* clients;
	
	uint32_t prev_ms;
	int udp_rc;

	unsigned short width;
	unsigned short height;

	bool is_debug;
} rtsp_streamer_t;

typedef enum {
    RTSP_OPTIONS,
    RTSP_DESCRIBE,
    RTSP_SETUP,
    RTSP_PLAY,
    RTSP_TEARDOWN,
    RTSP_UNKNOWN
} rtsp_command_type;

typedef struct {
	rtsp_command_type type;
	char presentation[RTSP_PARAM_MAX_SIZE];
	char stream[RTSP_PARAM_MAX_SIZE];
	char host[RTSP_HOSTNAME_MAX_SIZE];
} rtsp_command;

typedef struct {
	int id;
	int client;
	int stream_id;

	uint16_t rtp_port;
	uint16_t rtcp_port;

	rtsp_streamer_t* streamer;
	rtsp_command command;

	uint32_t cseq;
	uint32_t content_length;

	bool is_debug;
	bool is_streaming;
	bool is_stopped;
	bool is_tcp_transport;
} rtsp_session_t;

#endif // __RTSP__H
