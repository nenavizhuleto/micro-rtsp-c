#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "streamer.h"
#include "linked_list.h"
#include "session.h"

static inline void rtsp_socker_peer_addr(int __peer_sock, uint32_t *__peer_addr, uint16_t *__peer_port) {
    struct sockaddr_in __peer_r;
    socklen_t __peer_len = sizeof(__peer_r);
    if(getpeername(__peer_sock, (struct sockaddr*)&__peer_r, &__peer_len) < 0) {
        *__peer_addr = 0;
        *__peer_port = 0;
    } else {
        *__peer_port  = __peer_r.sin_port;
        *__peer_addr = __peer_r.sin_addr.s_addr;
    }
}

static inline ssize_t rtsp_udp_socket_send(int __udp_sock, const void *__udp_buf, size_t __udp_len, uint32_t __udp_addr, uint16_t __udp_port)
{
    struct sockaddr_in __udp_addr_in;

    __udp_addr_in.sin_family      = AF_INET;
    __udp_addr_in.sin_addr.s_addr = __udp_addr;
    __udp_addr_in.sin_port = htons(__udp_port);

    return sendto(__udp_sock, __udp_buf, __udp_len, 0, (struct sockaddr *) &__udp_addr_in, sizeof(__udp_addr_in));
}

static inline int rtsp_udp_socket_create(uint16_t __udp_port)
{
    struct sockaddr_in __udp_addr;

    __udp_addr.sin_family      = AF_INET;
    __udp_addr.sin_addr.s_addr = INADDR_ANY;

    int __udp_s     = socket(AF_INET, SOCK_DGRAM, 0);
    __udp_addr.sin_port = htons(__udp_port);

    if (bind(__udp_s, (struct sockaddr*) &__udp_addr, sizeof(__udp_addr)) != 0) {
        close(__udp_s);
        __udp_s = 0;
    }

    return __udp_s;
}

void rtsp_streamer_init(rtsp_streamer_t* streamer, uint16_t width, uint16_t height) {
	streamer->rtp_port = 0;
	streamer->rtcp_port = 0;

	streamer->cseq = 0;
	streamer->timestamp = 0;
	streamer->send_idx = 0;

	streamer->rtp_sock = 0;
	streamer->rtcp_sock = 0;

	streamer->width = width;
	streamer->height = height;

	streamer->clients = NULL;

	streamer->prev_ms = 0;
	streamer->udp_rc = 0;

	streamer->is_debug = false;

	streamer->host = "127.0.0.1:554";
	streamer->presentation = "mjpeg";
	streamer->stream = "1";
}

void rtsp_streamer_deinit_session(void* session) {
	rtsp_session_deinit((rtsp_session_t*)session);
}

void rtsp_streamer_deinit(rtsp_streamer_t* streamer) {
	llist_foreach(streamer->clients, rtsp_streamer_deinit_session);
	llist_item_t* client = streamer->clients;
	while (client != NULL) {
		llist_remove_item(client);
		client = client->next;
	}
}

void rtsp_streamer_add_session(rtsp_streamer_t* streamer, rtsp_session_t* session) {
	llist_item_t* item = llist_init((void*)session);
	if (streamer->clients) {
		llist_append(streamer->clients, item);
	} else {
		streamer->clients = item;
	}
}

void rtsp_streamer_set_uri(rtsp_streamer_t* streamer, char* host, char* presentation, char* stream) {
	streamer->host = host;
	streamer->presentation = presentation;
	streamer->stream = stream;
}

int rtsp_streamer_send_rtp_packet(rtsp_streamer_t* streamer, const uint8_t* jpeg, int len, int frag_offset, const uint8_t* quant_0_tbl, const uint8_t* quant_1_tbl) {


	#define RTP_HEADER_SIZE 12
	#define JPEG_HEADER_SIZE 8
	#define MAX_FRAG_SIZE 1100

	int frag_len = MAX_FRAG_SIZE;

	if (frag_len + frag_offset > len)
		frag_len = len - frag_offset;

	bool is_last_frag = (frag_offset + frag_len) == len;

	if (llist_is_empty(streamer->clients)) {

		return is_last_frag ? 0 : frag_offset;
	}

	bool include_quant_tbl = quant_0_tbl && quant_1_tbl && frag_offset == 0;
	uint8_t q = include_quant_tbl ? 128 : 0x5e;

	static char buf[2048];

	int rtp_packet_size = frag_len + RTP_HEADER_SIZE + JPEG_HEADER_SIZE + (include_quant_tbl ? (4 + 64 * 2) : 0);


	memset(buf, 0x00, sizeof(buf));

	buf[0]  = '$';
	buf[1]  = 0;
	buf[2]  = (rtp_packet_size & 0x0000FF00) >> 8;
	buf[3]  = (rtp_packet_size & 0x000000FF);
	buf[4]  = 0x80;
	buf[5]  = 0x1a | (is_last_frag ? 0x80 : 0x00);
	buf[7]  = streamer->cseq & 0x0FF;
	buf[6]  = streamer->cseq >> 8;
	buf[8]  = (streamer->timestamp & 0xFF000000) >> 24;
	buf[9]  = (streamer->timestamp & 0x00FF0000) >> 16;
	buf[10] = (streamer->timestamp & 0x0000FF00) >> 8;
	buf[11] = (streamer->timestamp & 0x000000FF);
	buf[12] = 0x13;
	buf[13] = 0xf9;
	buf[14] = 0x7e;
	buf[15] = 0x67;
	buf[16] = 0x00;
	buf[17] = (frag_offset & 0x00FF0000) >> 16;
	buf[18] = (frag_offset & 0x0000FF00) >> 8;
	buf[19] = (frag_offset & 0x000000FF);
	buf[20] = 0x00;
	buf[21] = q;
	buf[22] = streamer->width / 8;
	buf[23] = streamer->height / 8;

	int header_len = 24;

	if (include_quant_tbl) {
		buf[24] = 0;
		buf[25] = 0;
		buf[26] = 0;

		int num_quant_bytes = 64;
		buf[27] = 2 * num_quant_bytes;

		header_len += 4;

		memcpy(buf + header_len, quant_0_tbl, num_quant_bytes);
		header_len += num_quant_bytes;

		memcpy(buf + header_len, quant_1_tbl, num_quant_bytes);
		header_len += num_quant_bytes;
	}

	memcpy(buf + header_len, jpeg + frag_offset, frag_len);
	frag_offset += frag_len;

	streamer->cseq++;

	uint32_t addr;
	uint16_t port;

	llist_item_t* client = streamer->clients;
	rtsp_session_t* session = NULL;
	while (client != NULL) {
		session = (rtsp_session_t*)client->value;
		if (session->is_streaming && !session->is_stopped) {
			if (session->is_tcp_transport) {
				send(session->client, buf, rtp_packet_size + 4, 0);
			} else {
				rtsp_socker_peer_addr(session->client, &addr, &port);
				rtsp_udp_socket_send(streamer->rtp_sock, &buf[4], rtp_packet_size, addr, session->rtp_port);
			}
		}

		client = client->next;
	}

	return is_last_frag ? 0 : frag_offset;
}



bool rtsp_streamer_init_udp_transport(rtsp_streamer_t* streamer) {
	if (streamer->udp_rc != 0) {
		++streamer->udp_rc;
		return true;
	}

	for (uint16_t p = 6970; p < 0xFFFE; p += 2) {
		streamer->rtp_sock = rtsp_udp_socket_create(p);
		if (streamer->rtp_sock) {
			streamer->rtcp_sock = rtsp_udp_socket_create(p + 1);
			if (streamer->rtcp_sock) {
				streamer->rtp_port = p;
				streamer->rtcp_port = p + 1;
				break;
			} else {
				close(streamer->rtp_sock);
				close(streamer->rtcp_sock);
			}
		}
	}

	++streamer->udp_rc;
	return true;
}
void rtsp_streamer_deinit_udp_transport(rtsp_streamer_t* streamer) {
	--streamer->udp_rc;
	if (streamer->udp_rc == 0) {
		streamer->rtp_port = 0;
		streamer->rtcp_port = 0;
		close(streamer->rtp_sock);
		close(streamer->rtcp_sock);
		streamer->rtp_sock = 0;
		streamer->rtcp_sock = 0;
	}
}

bool rtsp_streamer_start(rtsp_streamer_t* streamer, uint32_t read_timeout_ms) {
	bool ret = true;

	llist_item_t* client = streamer->clients;
	while (client != NULL) {

		rtsp_session_t* session = (rtsp_session_t*)client->value;
		ret &= rtsp_session_start(session, read_timeout_ms);

		client = client->next;

		if (session->is_stopped) {
			rtsp_session_deinit(session);
			llist_remove_item(client);
		}
	}

	return ret;
}

bool rtsp_find_jpeg_header(const uint8_t** data, uint32_t *len, uint8_t marker) {
	// NOTE: https://en.wikipedia.org/wiki/JPEG_File_Interchange_Format
	const uint8_t* bytes = *data;

	while (bytes - *data < *len) {
		uint8_t framing = *bytes++;
		if (framing != 0xff) {
			printf("malformed jpeg, framing=%x\n", framing);
			return false;
		}

		uint8_t typecode = *bytes++;
		if (typecode == marker) {
			uint32_t skipped = bytes - *data;


			*data = bytes;
			*len -=skipped;

			return true;
		} else {
			switch (typecode) {
			case 0xd8:
				break;
			case 0xe0:
			case 0xdb:
			case 0xc4:
			case 0xc0:
			case 0xda:
				uint32_t len = bytes[0] * 256 + bytes[1];
				bytes += len;
				break;
			default:
				break;

			}
		}
	}

	printf("failed to find jpeg marker 0x%x", marker);

	return false;
}

void rtsp_skip_scan_bytes(const uint8_t** data) {
	const uint8_t* bytes = *data;

	while (true) { // FIXME:
		while (*bytes++ != 0xff);

		if (*bytes++ != 0) {
			*data = bytes - 2;
			return;
		}
	}
}

void rtsp_next_jpeg_block(const uint8_t** data) {
	uint32_t len = (*data)[0] * 256 + (*data)[1];
	*data += len;
}

bool rtsp_decode_jpeg_file(const uint8_t** data, uint32_t* len, const uint8_t** qtable_0, const uint8_t** qtable_1) {
	const uint8_t *bytes = *data;

	if (!rtsp_find_jpeg_header(&bytes, len, 0xd8)) {
		return false;
	}

	*qtable_0 = NULL;
	*qtable_1 = NULL;

	const uint8_t* quant_start = *data;
	const uint32_t quant_len = *len;

	if (!rtsp_find_jpeg_header(&quant_start, &quant_len, 0xdb)) {
		printf("failed to find quant table 0\n");
	} else {

		*qtable_0 = quant_start + 3;
		rtsp_next_jpeg_block(&quant_start);

		if (!rtsp_find_jpeg_header(&quant_start, &quant_len, 0xdb)) {
			printf("failed to find quant table 1\n");
		} else {
		}

		*qtable_1 = quant_start + 3;
		rtsp_next_jpeg_block(&quant_start);
	}

	if (!rtsp_find_jpeg_header(data, len, 0xda)) {
		return false;
	}

	uint32_t sos_len = (*data)[0] * 256 + (*data)[1];
	*data += sos_len;
	*len -= sos_len;

	const uint8_t* end_marker = *data;
	uint32_t end_len = *len;

	rtsp_skip_scan_bytes(&end_marker);

	if (!rtsp_find_jpeg_header(&end_marker, &end_len, 0xd9)) {
		return false;
	}

	*len = end_marker - *data;

	return true;
}

void rtsp_streamer_stream_frame(rtsp_streamer_t* streamer, const uint8_t* data, uint32_t len, uint32_t ms) {
	if (streamer->prev_ms == 0) {
		streamer->prev_ms = ms;
	}

	uint32_t delta_ms = (ms >= streamer->prev_ms) ? ms - streamer->prev_ms : 1000;
	streamer->prev_ms = ms;

	const uint8_t *qtable_0, *qtable_1;

	if (!rtsp_decode_jpeg_file(&data, &len, &qtable_0, &qtable_1)) {
		return;
	}

	int offset = 0;
	do {
		offset = rtsp_streamer_send_rtp_packet(streamer, data, len, offset, qtable_0, qtable_1);
	} while (offset != 0);

	uint32_t units = 90000;
	streamer->timestamp += (units * delta_ms / 1000);
	streamer->send_idx++;
	if (streamer->send_idx > 1) streamer->send_idx = 0;
}
