#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <strings.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "rtsp.h"
#include "streamer.h"
#include "session.h"

#define RTSP_WRITE_RESPONSE(format, ...) snprintf(response, sizeof(response), format, __VA_ARGS__)

static char transport[255];
static char sdp_buf[1024];
static char url_buf[1024];

bool rtsp_session_parse_request(rtsp_session_t* session, char* request, uint32_t request_size);

void rtsp_session_handle_command_option(rtsp_session_t* session);
void rtsp_session_handle_command_describe(rtsp_session_t* session);
void rtsp_session_handle_command_setup(rtsp_session_t* session);
void rtsp_session_handle_command_play(rtsp_session_t* session);



void rtsp_session_reset_command(rtsp_session_t* session) {
	memset(session->command.presentation, 0x00, sizeof(session->command.presentation));
	memset(session->command.stream, 0x00, sizeof(session->command.stream));
	memset(session->command.host, 0x00, sizeof(session->command.host));
	session->content_length = 0;
}

void rtsp_session_init(rtsp_session_t* session, int client, rtsp_streamer_t* streamer) {
	rtsp_session_reset_command(session);

	session->client = client;
	session->streamer = streamer;
	session->id = rand() | 0x8000000;
	session->stream_id = -1;
	session->rtp_port = 0;
	session->rtcp_port = 0;
	session->is_tcp_transport = false;
	session->is_streaming = false;
	session->is_stopped = false;
	session->cseq = 0;
	session->command.type = RTSP_UNKNOWN;
	session->is_debug = false;
}

void rtsp_session_deinit(rtsp_session_t* session) {
	rtsp_streamer_deinit_udp_transport(session->streamer);
	close(session->client);
}

bool rtsp_session_init_transport(rtsp_session_t* session){
	if (!session->is_tcp_transport) {
		return rtsp_streamer_init_udp_transport(session->streamer);
	}
	return true;
}

static char* rtsp_session_parse_numeric_header(char* buf, uint32_t *number, uint32_t max_length) {
	int count = max_length;

	// skipping space after ':'
	while (*buf  && count > 0 && (*buf == ' ' || *buf == '\t'))  {
	    ++buf;
	    --count;
	}

	if (!*buf || !isdigit(*buf) || !count)
	    return NULL;

	char *number_start = buf;

	while(*buf && isdigit(*buf) && count > 0) {
	    ++buf;
	    --count;
	}

	if (count == 0)
	    return NULL;

	char c = *buf;

	*buf = '\0';
	*number = atoi(number_start);
	*buf = c;

	return buf;
}

bool rtsp_session_parse_request(rtsp_session_t* session, char* request, uint32_t request_size) {
	static char command[20];

	rtsp_session_reset_command(session);

	char *cursor = request;
	int dest_pos = 0;

	while (dest_pos < 19 && *cursor != ' ' && *cursor != '\t') {
		command[dest_pos++] = *(cursor++);
	}

	command[dest_pos] = '\0';

	while (*cursor && isspace(*cursor))
		++cursor;

	if (!*cursor || 0 != strncasecmp("rtsp://", cursor, 7))
		return false;

	cursor += 7;

	for (dest_pos = 0; *cursor && !isspace(*cursor) && *cursor != '/'; ++cursor, ++dest_pos) {
		if (dest_pos == RTSP_HOSTNAME_MAX_SIZE)
			return false;

		session->command.host[dest_pos] = *cursor;
	}

	if (*cursor != '/')
		return false;

	session->command.host[dest_pos] = '\0';

	if (session->is_debug) printf("host-port: %s\n", session->command.host);

	while (*cursor == '/')
		++cursor;

	for (dest_pos = 0; *cursor && !isspace(*cursor) && *cursor != '/'; ++cursor, ++dest_pos) {
		if (dest_pos == RTSP_PARAM_MAX_SIZE)
			return false;

		session->command.presentation[dest_pos] = *cursor;
	}

	if (*cursor != '/')
		return false;

	session->command.presentation[dest_pos] = '\0';

	if (session->is_debug) printf("+ presentation: %s\n", session->command.presentation);

	while (*cursor == '/')
		++cursor;

	for (dest_pos = 0; *cursor && !isspace(*cursor) && *cursor != '/'; ++cursor, ++dest_pos) {
		if (dest_pos == RTSP_PARAM_MAX_SIZE)
			return false;

		session->command.stream[dest_pos] = *cursor;
	}

	session->command.stream[dest_pos] = '\0';

	while (*cursor == '/')
		++cursor;

	if (*cursor != ' ' && *cursor != '\t')
		return false;

	if (session->is_debug) printf("+ stream: %s\n", session->command.stream);

	while (isspace(*cursor))
		++cursor;

	if (0 != strncmp("RTSP/", cursor, 5))
		return false;

	cursor += 5;
	if (!isdigit(*cursor) || cursor[1] != '.' || !isdigit(cursor[2]))
		return false;

	cursor += 3;

	int left;

	if (session->is_debug) printf("analyzing headers\n");

	for (;;) {
		while (*cursor && *cursor != '\r' && cursor[1] != '\n')
			++cursor;

		if (!*cursor || (*cursor != '\r' && cursor[1] != '\n'))
			return false;

		cursor += 2;

		if (!*cursor)
			break;

		left = request_size - (cursor - request);

		if (session->is_debug) {
			printf("* left: %d: '", left);
			for (char *s = cursor; *s && (s - cursor) < 20; ++s) {
				if (*s == '\r')
					printf("<CR>");
				else if (*s == '\n')
					printf("<LF>");
				else if (isprint(*s))
					putchar(*s);
				else
					printf("<0x%x>", *s);
			}

			puts("'");
		}

		if (0 == strncmp("CSeq:", cursor, 5)) {
			uint32_t cseq;

			left -= 5;
			cursor = rtsp_session_parse_numeric_header(cursor + 5, &cseq, left);

			if (cursor == NULL)
				return false;

			session->cseq = cseq;

			if (session->is_debug) printf("+ got cseq: %u\n", cseq);

			continue;
		}

		if (0 == strncmp("Content-Length", cursor, 15)) {
			left -= 15;
			cursor = rtsp_session_parse_numeric_header(cursor + 15, &session->content_length, left);

			if (cursor == NULL)
				return false;

			if (session->is_debug) printf("+ got content-length: %u\n", session->content_length);

			continue;
		}

		for (char *p = cursor; *p; ++p) {
			if (*p == '\r' && p[1] == '\n') {
				if (p[2] != ' ' && p[2] != '\t')
					break;

				*p = ' ';
				++p;
				*p = ' ';
			}
		}

		if (session->command.type == RTSP_SETUP && 0 == strncmp("Transport:", cursor, 10)) {
			cursor += 10;

			while (*cursor && isspace(*cursor))
				++cursor;

			if (0 != strncmp(cursor, "RTP/AVP", 7))
				return false;

			cursor += 7;

			if (0 == strncmp(cursor, "/TCP", 4)) {
				session->is_tcp_transport = true;
				cursor += 4;
			} else {
				session->is_tcp_transport = false;
			}

			if (session->is_debug) printf("+ Transport is %s\n", session->is_tcp_transport ? "TCP" : "UDP");

			session->rtp_port = 0;

			char *next_part, last_char;

			for (;;) {
				while (*cursor == ';' || *cursor == ' ' || *cursor == '\t')
					++cursor;

				if (!*cursor)
					return false;

				if (*cursor == '\r' && cursor[1] == '\n')
					break;

				next_part = strpbrk(cursor, ";\r");

				if (!next_part)
					return false;

				last_char = *next_part;

				if (0 == strncmp(cursor, "client_port=", 12)) {
					char *p = (cursor += 12);

					while (isdigit(*p))
						++p;

					if (p == cursor)
						return false;

					*p = '\0';

					session->rtp_port = atoi(cursor);
					session->rtcp_port = session->rtp_port + 1;

					if (session->is_debug) printf("+ got client port: %u\n", session->rtp_port);
				}

				*next_part = last_char;

				cursor = next_part;
			}
		}

		if (session->is_debug && *cursor != '\r') printf("? unknown header ?\n");

		while (*cursor && *cursor != '\r')
			++cursor;
	}

	printf("\n+ RTSP command: %s\n", command);
	return true;
}

rtsp_command rtsp_session_handle_request(rtsp_session_t* session, char* request, uint32_t request_size) {
	if (rtsp_session_parse_request(session, request, request_size)) {
		switch (session->command.type) {
			case RTSP_OPTIONS: rtsp_session_handle_command_option(session); break;
			case RTSP_DESCRIBE: rtsp_session_handle_command_describe(session); break;
			case RTSP_SETUP: rtsp_session_handle_command_setup(session); break;
			case RTSP_PLAY: rtsp_session_handle_command_play(session); break;
			default:
				printf("handle_request: unknown command type: %d\n", session->command.type);
				break;
		}
	} else {
	}

	return session->command;
}


void rtsp_session_handle_command_option(rtsp_session_t* session) {
	static char response[1024];
	RTSP_WRITE_RESPONSE(
		"RTSP/1.0 200 OK\r\nCSeq: %u\r\n"
		"Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n\r\n",
		session->cseq
	);

	send(session->client, response, strlen(response), 0);
}

bool rtsp_session_validate_stream_id(rtsp_session_t* session) {
	session->stream_id = -1;
	if (session->streamer->presentation == session->command.presentation &&
	    session->streamer->stream == session->command.stream) {
		session->stream_id = 0;
	}

	return session->stream_id;
}

char const* rtsp_session_generate_date_header() {
	static char date_buf[200];
	time_t t = time(NULL);
	strftime(date_buf, sizeof(date_buf), "Date: %a, %b %d %Y %H:%M:%S GMT", gmtime(&t));
	return date_buf;
}

void rtsp_session_handle_command_describe(rtsp_session_t* session) {
	static char response[1024];
	if (!rtsp_session_validate_stream_id(session)) {
		RTSP_WRITE_RESPONSE(
			"RTSP/1.0 404 Stream Not Found\r\nCSeq: %u\r\n%s\r\n",
			session->cseq,
			rtsp_session_generate_date_header()
		);

		send(session->client, response, strlen(response), 0);
		return;
	}

	static char buf[256];
	char * clnptr;

	strcpy(buf, session->command.host);
	clnptr = strstr(buf, ":");
	if (clnptr != NULL) clnptr[0] = 0x00;

	snprintf(sdp_buf, sizeof(sdp_buf),
	  "v=0\r\n"
	  "o=- %d 1 IN IP4 %s\r\n"
	  "s=\r\n"
	  "t=0 0\r\n"
	  "m=video 0 RTP/AVP 26\r\n"
	  "c=IN IP4 0.0.0.0\r\n",
	  rand(),
	  buf
	);

	snprintf(url_buf, sizeof(url_buf),
	  "rtsp://%s/%s/%s",
	  session->command.host,
	  session->command.presentation,
	  session->command.stream
	);

	RTSP_WRITE_RESPONSE(
		"RTSP/1.0 200 OK\r\nCSeq: %u\r\n"
		"%s\r\n"
		"Content-Base: %s/\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %d\r\n\r\n"
		"%s",
		session->cseq,
		rtsp_session_generate_date_header(),
		url_buf,
		(int)strlen(sdp_buf),
		sdp_buf
	);

	send(session->client, response, strlen(response), 0);
}

void rtsp_session_handle_command_setup(rtsp_session_t* session) {
	static char response[1024];

	if (!rtsp_session_init_transport(session)) {
		printf("+ failed to init session transport\n");
		// TODO: handle error
		return;
	}

	if (session->is_tcp_transport) {
		snprintf(transport, sizeof(transport), "RTP/AVP/TCP;unicast;interleaved=0-1");
	} else {
		snprintf(transport, sizeof(transport),
			"RTP/AVP;unicast;destination=127.0.0.1;source=127.0.0.1;client_port=%i-%i;server_port=%i-%i",
			session->rtp_port,
			session->rtcp_port,
			session->streamer->rtp_port,
			session->streamer->rtcp_port
		);
	}

	RTSP_WRITE_RESPONSE(
		"RTSP/1.0 200 OK\r\nCSeq: %u\r\n"
		"%s\r\n"
		"Transport: %s\r\n"
		"Session: %i\r\n\r\n",
		session->cseq,
		rtsp_session_generate_date_header(),
		transport,
		session->id
	);

	send(session->client, response, strlen(response), 0);
}

void rtsp_session_handle_command_play(rtsp_session_t* session) {
	static char response[1024];

	RTSP_WRITE_RESPONSE(
		"RTSP/1.0 200 OK\r\nCSeq: %u\r\n"
		"%s\r\n"
		"Range: npt=0.000-\r\n"
		"Session: %i\r\n"
		"RTP-Info: url=rtsp://127.0.0.1:8554/mjpeg/1/track\r\n\r\n",
		session->cseq,
		rtsp_session_generate_date_header(),
		session->id
	);

	send(session->client, response, strlen(response), 0);
}

static inline int rtsp_client_read_tm(int client, char *buf, size_t size, uint32_t timeout_ms) {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout_ms * 1000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    int res = recv(client, buf, size, 0);
    if (res > 0) {
        return res;
    } else if (res == 0) {
        return 0;
    } else {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
            return -1;
        else
            return 0;
    };
}

bool rtsp_session_start(rtsp_session_t* session, uint32_t read_timeout_ms) {

	if (session->is_stopped) {
		return false;
	}

	static uint32_t buf_pos = 0;
	static enum {
		HDR_STATE_UNKNOWN,
		HDR_STATE_GOT_METHOD,
		HDR_STATE_INVALID
	} state = HDR_STATE_UNKNOWN;

	static char received[RTSP_BUFFER_SIZE];

	if (buf_pos == 0 || buf_pos >= sizeof(received) - 1) {
		memset(received, 0x00, sizeof(received));
		buf_pos = 0;
		state = HDR_STATE_UNKNOWN;
	}

	int res = rtsp_client_read_tm(session->client, received + buf_pos, sizeof(received) - buf_pos - 1, read_timeout_ms);
	if (res > 0) {
		buf_pos += res;
		received[buf_pos] = '\0';

		if (session->is_debug) printf("+ read %d bytes\n", res);
		if (session->is_debug) printf("+ received: \n%s\n", received);

		if (state == HDR_STATE_UNKNOWN && buf_pos >= 6) {
			if (NULL != strstr(received, "\r\n")) {
				char *s = received;

				if (*s == '\r' && *(s + 1) == '\n') s += 2;

				rtsp_session_reset_command(session);

				if (strncmp(s, "OPTIONS ", 8) == 0) session->command.type = RTSP_OPTIONS;
				else if (strncmp(s, "DESCRIBE ", 9) == 0) session->command.type = RTSP_DESCRIBE;
				else if (strncmp(s, "SETUP ", 6) == 0) session->command.type = RTSP_SETUP;
				else if (strncmp(s, "PLAY ", 5) == 0) session->command.type = RTSP_PLAY;
				else if (strncmp(s, "TEARDOWN ", 5) == 0) session->command.type = RTSP_TEARDOWN;

				if (session->command.type != RTSP_UNKNOWN) {
					state = HDR_STATE_GOT_METHOD;
				} else {
					state = HDR_STATE_INVALID;
				}
			}
		}

		if (state != HDR_STATE_UNKNOWN) {
			char *s = strstr(buf_pos > 4 ? received + buf_pos - 4 : received, "\r\n\r\n");

			if (s == NULL) return true;

			if (state == HDR_STATE_INVALID) {
				int len = snprintf(received, sizeof(received), "RTSP/1.0 400 Bad Request\r\nCSeq: %u\r\n\r\n", session->cseq);
				send(session->client, received, len, 0);
				buf_pos = 0;
				return false;
			}
		}

		rtsp_command command = rtsp_session_handle_request(session, received, res);

		if (command.type == RTSP_PLAY) {
			session->is_streaming = true;
		} else if (command.type == RTSP_TEARDOWN) {
			session->is_stopped = true;
		}

		state = HDR_STATE_UNKNOWN;
		buf_pos = 0;

		return true;
	} else if (res == 0) {
		printf("+ client closed socket, exiting\n");
		session->is_stopped = true;
		return true;
	} else {
		return false;
	}
}
