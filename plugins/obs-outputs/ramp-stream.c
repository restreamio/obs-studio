#include "ramp-stream.h"
#include "obs-output-ver.h"

// Internal functions

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifdef __cplusplus
}
#endif

// In memory recovery packet buffer limits
const int RAMP_PID_UPPER_LIMIT = 0xF000;
const int RAMP_PID_UPPER_DECREASE = 0x8000;
const int RAMP_PID_QUEUE_SIZE = 0x2000;

// Ramp base functions

static struct ramp_packet_int *
ramp_alloc_udp_packet(ramp_stream_int *stream_int, unsigned short pid,
		      int add_size)
{
	ramp_packet_int *pkt = malloc(sizeof(ramp_packet_int) +
				      stream_int->tp_size - 1 + add_size);
	memset(pkt, 0, sizeof(struct ramp_packet_int));

	pkt->pid = pid;
	pkt->data_size = stream_int->tp_size + add_size;

	return pkt;
}

static unsigned char *ramp_crypt_buffer = NULL;

static unsigned char *ramp_encrypt(ramp_stream_int *stream_int,
				   unsigned char *buffer, int size, bool crypt)
{
	if (!ramp_crypt_buffer)
		ramp_crypt_buffer = malloc(5600 + ramp_packet_int_header_size);

	unsigned char cs = 0;
	for (int i = 0, j = 0; i < size; i++, j = ++j % 256) {
		cs += i != 2 ? buffer[i] : 0;
		ramp_crypt_buffer[i] = crypt ? buffer[i] ^ stream_int->c_key[j]
					     : buffer[i];
	}

	ramp_crypt_buffer[2] = crypt ? cs ^ stream_int->c_key[2] : cs;
	return ramp_crypt_buffer;
}

static unsigned char *ramp_decrypt(ramp_stream_int *stream_int,
				   unsigned char *buffer, int size)
{
	if (!ramp_crypt_buffer)
		ramp_crypt_buffer = malloc(5600 + ramp_packet_int_header_size);

	unsigned char cs = 0;
	for (int i = 0, j = 0; i < size; i++, j = ++j % 256) {
		ramp_crypt_buffer[i] = buffer[i] ^ stream_int->c_key[j];
		cs += i != 2 ? ramp_crypt_buffer[i] : 0;
	}

	return ramp_crypt_buffer[2] == cs ? ramp_crypt_buffer : NULL;
}

static bool ramp_send_udp_packet(struct ramp_stream_int *stream_int,
				 struct ramp_packet_int *pkt, bool add)
{
	if (!pkt)
		return true;

	//debug("Send pid=%d, size=%d", (int)pkt->pid,
	//	 pkt->data_used + ramp_packet_int_header_size);

	bool encrypt =
		!(pkt->pid == 1 || (pkt->pid == 3 && !stream_int->connect_ack));

	unsigned char *buf = ramp_encrypt(
		stream_int, (unsigned char *)&pkt->pid,
		pkt->data_used + ramp_packet_int_header_size, encrypt);

	int res = sendto(stream_int->ext_socket, buf,
			 pkt->data_used + ramp_packet_int_header_size, 0,
			 (const struct sockaddr *)&stream_int->ext_to,
			 sizeof(struct sockaddr_in));

	if (res != pkt->data_used + ramp_packet_int_header_size) {
		if (pkt->pid < 100 || add)
			free(pkt);

		return false;
	}

	if (pkt->pid < 100) {
		free(pkt);
		return true;
	}

	if (!add)
		return true;

	pkt->next = NULL;

	if (stream_int->tp_sent_last) {
		stream_int->tp_sent_last->next = pkt;
		stream_int->tp_sent_last = pkt;
		stream_int->tp_sent_count++;
	} else {
		stream_int->tp_sent_first = stream_int->tp_sent_last = pkt;
		stream_int->tp_sent_count = 1;
	}

	if (stream_int->tp_pid > RAMP_PID_UPPER_LIMIT) {
		struct ramp_packet_int *cur_pkt = stream_int->tp_sent_first;
		while (cur_pkt) {
			cur_pkt->pid -= RAMP_PID_UPPER_DECREASE;
			cur_pkt = cur_pkt->next;
		}

		stream_int->tp_pid -= RAMP_PID_UPPER_DECREASE;
	}

	struct ramp_packet_int *cur_pkt = stream_int->tp_sent_first;
	while (stream_int->tp_sent_count > RAMP_PID_QUEUE_SIZE * 2) {
		stream_int->tp_sent_first = stream_int->tp_sent_first->next;
		stream_int->tp_sent_count--;
		free(cur_pkt);

		if (!stream_int->tp_sent_first) {
			stream_int->tp_sent_last = NULL;
			stream_int->tp_sent_count = 0;
			break;
		}
	}

	if (stream_int->fec) {
		struct ramp_packet_int *pkt1 = NULL;
		struct ramp_packet_int *pkt2 = NULL;

		struct ramp_packet_int *cur_pkt = stream_int->tp_sent_first;
		while (cur_pkt) {
			if (cur_pkt->pid == pkt->pid - 20) {
				if (cur_pkt->fec_sent)
					break;

				pkt1 = cur_pkt;
			}

			if (cur_pkt->pid == pkt->pid - 10) {
				if (cur_pkt->fec_sent)
					break;

				pkt2 = cur_pkt;
			}

			if (pkt1 && pkt2)
				break;

			cur_pkt = cur_pkt->next;
		}

		if (pkt1 && pkt2) {
			stream_int->stat_pkt_sent_fec++;
			pkt1->fec_sent = true;
			pkt2->fec_sent = true;

			struct ramp_packet_int *fec_pkt =
				ramp_alloc_udp_packet(stream_int, 9, 9);
			int fec_len = max(pkt1->data_used, pkt2->data_used);
			fec_pkt->data_used = 9 + fec_len;

			*(unsigned short *)&fec_pkt->data = pkt1->pid;
			*(unsigned short *)(&fec_pkt->data + 2) =
				(unsigned short)pkt1->data_used;
			*(unsigned short *)(&fec_pkt->data + 4) = pkt2->pid;
			*(unsigned short *)(&fec_pkt->data + 6) =
				(unsigned short)pkt2->data_used;

			unsigned char cs1 = 0;
			for (int i = 0;
			     i < pkt1->data_used + ramp_packet_int_header_size;
			     i++)
				cs1 += i != 2 ? ((unsigned char *)&pkt1->pid)[i]
					      : 0;

			unsigned char cs2 = 0;
			for (int i = 0;
			     i < pkt2->data_used + ramp_packet_int_header_size;
			     i++)
				cs2 += i != 2 ? ((unsigned char *)&pkt2->pid)[i]
					      : 0;

			*(unsigned char *)(&fec_pkt->data + 8) = cs1 ^ cs2;

			for (int i = 0; i < fec_len; i++) {
				unsigned char b1 = i < pkt1->data_used
							   ? (&pkt1->data)[i]
							   : 0;
				unsigned char b2 = i < pkt2->data_used
							   ? (&pkt2->data)[i]
							   : 0;
				(&fec_pkt->data)[i + 9] = b1 ^ b2;
			}

			ramp_send_udp_packet(stream_int, fec_pkt, false);
		}
	}

	return true;
}

static void ramp_resesend_udp_req(ramp_stream_int *stream,
				  unsigned short *pid_set, int pid_count)
{
	if (!pid_count || !stream->tp_sent_first)
		return;

	//long cur_time = (long)time(0);

	struct ramp_packet_int *pkt = stream->tp_sent_first;
	int pid_index = 0;
	int pid_found = 0;

	while (pkt && pid_index < pid_count) {
		if (pkt->pid < pid_set[pid_index]) {
			pkt = pkt->next;
			continue;
		}

		if (pkt->pid > pid_set[pid_index]) {
			while (pkt->pid > pid_set[pid_index] &&
			       pid_index < pid_count) {
				pid_index++;
			}

			continue;
		}

		if (!pkt->resend)
			pkt->resend = true;

		stream->resend = true;

		pkt = pkt->next;
		pid_index++;
		pid_found++;
	}

	int total = 0;
	pkt = stream->tp_sent_first;
	while (pkt) {
		if (pkt->resend)
			total++;

		pkt = pkt->next;
	}

	//debug("Resend request, count=%d, from pid=%d, total=%d", pid_count, (int)*pid_set, total);
}

static bool ramp_resesend_udp_collected(ramp_stream_int *stream)
{
	if (!stream->resend)
		return false;

	//long cur_time = (long)time(0);

	struct ramp_packet_int *pkt = stream->tp_sent_first;
	int pid_index = 0;
	unsigned short first_pid = 0;
	int resend_count = 0;

	while (pkt) {
		if (pkt->resend) {
			if (!first_pid)
				first_pid = pkt->pid;

			//info("Resend pid=%d, size=%d", (int)pkt->pid, pkt->data_used);
			if (!ramp_send_udp_packet(stream, pkt, false))
				return true;

			//pkt->resend_time = cur_time;
			pkt->resend = false;
			stream->stat_pkt_sent_lost++;
			resend_count++;
			if (resend_count >= 10)
				return true;
		}

		pkt = pkt->next;
	}

	stream->resend = false;
	return true;
}

static void ramp_stream_send_test(ramp_stream_int *stream)
{
	for (int i = 0; i < 2; i++) {
		struct ramp_packet_int *pkt =
			malloc(sizeof(struct ramp_packet_int) + 1400 - 1);
		memset(pkt, 0, sizeof(struct ramp_packet_int));

		pkt->pid = 7;
		pkt->data_size = 1400;
		pkt->data_used = 1400;
		ramp_send_udp_packet(stream, pkt, false);

		pkt = malloc(sizeof(struct ramp_packet_int) + 2800 - 1);
		memset(pkt, 0, sizeof(struct ramp_packet_int));

		pkt->pid = 7;
		pkt->data_size = 2800;
		pkt->data_used = 2800;
		ramp_send_udp_packet(stream, pkt, false);

		pkt = malloc(sizeof(struct ramp_packet_int) + 5600 - 1);
		memset(pkt, 0, sizeof(struct ramp_packet_int));

		pkt->pid = 7;
		pkt->data_size = 5600;
		pkt->data_used = 5600;
		ramp_send_udp_packet(stream, pkt, false);
	}
}

static void ramp_confirm_udp(ramp_stream_int *stream, unsigned short pid)
{
	if (!stream->tp_sent_last)
		return;

	if (pid > stream->tp_sent_last->pid) {
		if (pid < RAMP_PID_UPPER_DECREASE)
			return;

		pid -= RAMP_PID_UPPER_DECREASE;
	}

	int count = 0;

	while (stream->tp_sent_first && stream->tp_sent_first->pid <= pid) {
		struct ramp_packet_int *next = stream->tp_sent_first->next;
		free(stream->tp_sent_first);
		stream->tp_sent_first = next;
		stream->tp_sent_count--;
		count++;
	}

	if (!stream->tp_sent_first) {
		stream->tp_sent_last = NULL;
		stream->tp_sent_count = 0;
	}

	//info("Confirm pid=%d, removed pkt count=%d", (int)pid, count);
}

static bool ramp_check_connection(ramp_stream_int *stream)
{
	if (!stream->alive)
		return false;

	if (stream->connect_ack)
		return true;

	long cur_time = (long)time(0);
	if (cur_time - stream->connect_send_time >= 2)
		stream->connect_send_time = 0;

	if (!stream->connect_send_time) {
		stream->connect_send_time = cur_time;

		struct ramp_packet_int *pkt =
			ramp_alloc_udp_packet(stream, 1, 0);
		memcpy(&pkt->data, stream->c_key, 256);
		pkt->data_used = 256;

		ramp_send_udp_packet(stream, pkt, false);

		pkt = ramp_alloc_udp_packet(stream, 1, 0);
		memcpy(&pkt->data, stream->c_key, 256);
		pkt->data_used = 256;

		struct sockaddr_in tmp = stream->ext_to;
		stream->ext_to = stream->ext_to10;
		ramp_send_udp_packet(stream, pkt, false);
		stream->ext_to = tmp;

		return false;
	}

	return false;
}

static void ramp_fec_state(ramp_stream_int *stream, bool fec)
{
	if (stream->fec != fec) {
		stream->fec = fec;
		info("FEC, state=%s", fec ? "enabled" : "disabled");
	}
}

/*
static inline AVal *flv_str(AVal *enc, const char *str) {
	enc->av_val = (char *)str;
	enc->av_len = (int)strlen(str);
	return enc;
}

static inline void enc_num_val(char **enc, char *end, char *name, double val) {
	AVal s;
	flv_str(&s, name);
	*enc = AMF_EncodeNamedNumber(*enc, end, &s, val);
}

static inline void enc_bool_val(char **enc, char *end, const char *name, bool val)
{
	AVal s;
	flv_str(&s, name);
	*enc = AMF_EncodeNamedBoolean(*enc, end, &s, val);
}

static inline void enc_str_val(char **enc, char *end, const char *name, const char *val)
{
	AVal s1, s2;
	flv_str(&s1, name);
	flv_str(&s2, val);
	*enc = AMF_EncodeNamedString(*enc, end, &s1, &s2);
}

static inline void enc_str(char **enc, char *end, const char *str) {
	AVal s;
	flv_str(&s, str);
	*enc = AMF_EncodeString(*enc, end, &s);
}
*/

static inline void set_aval(AVal *val, const char *str)
{
	bool valid = (str && *str);
	val->av_val = valid ? (char *)str : NULL;
	val->av_len = valid ? (int)strlen(str) : 0;
}

#define MILLISECOND_DEN 1000

static int32_t get_ms_time(struct encoder_packet *packet, int64_t val)
{
	return (int32_t)(val * MILLISECOND_DEN / packet->timebase_den);
}

#ifdef _WIN32
static DWORD WINAPI ramp_thread(LPVOID data)
{
#else
static void *ramp_thread(void *data)
{
#endif

	ramp_stream_int *stream_int = (ramp_stream_int *)data;
	if (!stream_int || !stream_int->alive) {
#ifdef _WIN32
		return 0;
#else
		return NULL;
#endif
	}

	debug("Work thread start");

	stream_int->recieve_time = time(0);

	const long reportPeriod = 30;
	long reportTime = time(0) + reportPeriod;

	bool acceptPacket = false;
	bool sleepFlag = false;

	while (stream_int->alive) {
		if (sleepFlag) {
			long curTime = time(0);
			if (curTime > stream_int->recieve_time + 20) {
				warn("Receive timeout");
				stream_int->alive = false;
				break;
			}

			if (curTime >= reportTime) {
				reportTime = curTime + reportPeriod;

				int lost_perc =
					stream_int->stat_pkt_sent_lost
						? (int)(((double)stream_int
								 ->stat_pkt_sent_lost) /
							(stream_int
								 ->stat_pkt_sent_regular +
							 stream_int
								 ->stat_pkt_sent_lost) *
							100)
						: 0;
				int q_perc = (int)(((double)stream_int
							    ->tp_sent_count) /
						   RAMP_PID_QUEUE_SIZE * 100);

				info("Stat, pkt sent regular=%d, repeat=%d (%d%%), fec=%d, queue size=%d (%d%%), recv lost=%d",
				     stream_int->stat_pkt_sent_regular,
				     stream_int->stat_pkt_sent_lost, lost_perc,
				     stream_int->stat_pkt_sent_fec,
				     stream_int->tp_sent_count, q_perc,
				     stream_int->stat_pkt_recv_lost);

				stream_int->stat_pkt_sent_regular = 0;
				stream_int->stat_pkt_sent_lost = 0;
				stream_int->stat_pkt_sent_fec = 0;
				stream_int->stat_pkt_recv_lost = 0;

				//ramp_stream_send_test(tun_stream, &ext_to);
			}

			msleep(1);
		}

		sleepFlag = true;

		// receive udp data from tunnel
		while (stream_int->alive) {
			socklen_t ext_from_len = sizeof(stream_int->ext_from);
			int res = recvfrom(
				stream_int->ext_socket,
				stream_int->ext_recv_buffer,
				stream_int->ext_recv_buffer_size, 0,
				(struct sockaddr *)&stream_int->ext_from,
				&ext_from_len);
			if (res <= 0)
				break;

			sleepFlag = false;

			unsigned char *buf = ramp_decrypt(
				stream_int,
				(unsigned char *)stream_int->ext_recv_buffer,
				res);
			if (!buf)
				continue;

			unsigned short pid = *(unsigned short *)buf;
			//debug("Recv pid=%d, size=%d", (int)pid, res);

			if (pid != 2 && stream_int->ext_to.sin_port !=
						stream_int->ext_from.sin_port) {
				//debug("Recv ignored, wrong ingest");
				continue;
			}

			stream_int->recieve_time = time(0);

			switch (pid) {
			case 2: // connect ack
				if (stream_int->connect_send_time &&
				    !stream_int->connect_ack) {
					stream_int->connect_ack = true;
					stream_int->tp_pid = 100;
					stream_int->tp_recv_pid = 99;

					stream_int->ext_to.sin_port =
						stream_int->ext_from.sin_port;

					info("Response from ingest=%d",
					     (int)ntohs(stream_int->ext_to
								.sin_port));
				}
				break;

			case 3: // disconnect
				debug("Disconnect packet");
				stream_int->alive = false;
				break;

			case 4: // resend lost
				res -= ramp_packet_int_header_size;
				ramp_resesend_udp_req(
					stream_int,
					(unsigned short
						 *)(buf +
						    ramp_packet_int_header_size),
					res >> 1);
				break;

			case 5: // confirm received
				ramp_confirm_udp(
					stream_int,
					*(unsigned short
						  *)(buf +
						     ramp_packet_int_header_size));

				// if noting was sent since prev confirm, resend the last packet
				if (!stream_int->sent_any_after_confirm &&
				    stream_int->tp_sent_last)
					ramp_send_udp_packet(
						stream_int,
						stream_int->tp_sent_last,
						false);

				stream_int->sent_any_after_confirm = false;
				stream_int->confirm_time = (long)time(0);
				break;

			case 8: // change MTU
				//stream->tp_size = *(unsigned short *)(buf + ramp_packet_int_header_size);
				//if(stream->tp_size > 2800)
				//	stream->tp_size = 2800;
				//
				//info("Set tunnel packet size=%d", (int)tun_stream->tp_size);
				break;

			case 9: // change FEC
				ramp_fec_state(
					stream_int,
					*(buf + ramp_packet_int_header_size) !=
						0);
				break;

			default: // regular packet
				acceptPacket = false;

#ifdef _WIN32
				EnterCriticalSection(&stream_int->critsec);
#else
				pthread_mutex_lock(&stream_int->mutex);
#endif

				if (res <= stream_int->int_send_buffer_size -
						    stream_int
							    ->int_send_buffer_used &&
				    pid == stream_int->tp_recv_pid + 1) {
					acceptPacket = true;

					res -= ramp_packet_int_header_size;
					memcpy(stream_int->int_send_buffer +
						       stream_int
							       ->int_send_buffer_used,
					       buf + ramp_packet_int_header_size,
					       res);
					stream_int->int_send_buffer_used += res;
				}

#ifdef _WIN32
				LeaveCriticalSection(&stream_int->critsec);
#else
				pthread_mutex_unlock(&stream_int->mutex);
#endif

				if (acceptPacket) {
					stream_int->tp_recv_pid++;
					if (stream_int->tp_recv_pid >=
					    RAMP_PID_UPPER_LIMIT)
						stream_int->tp_recv_pid = 99;

					struct ramp_packet_int *pkt =
						ramp_alloc_udp_packet(
							stream_int, 5, 0);

					pkt->data_used = 2;
					*((unsigned short *)&pkt->data) = pid;
					ramp_send_udp_packet(stream_int, pkt,
							     false);
				} else
					stream_int->stat_pkt_recv_lost++;
			}
		}

		if (!ramp_check_connection(stream_int))
			continue;

		if (ramp_resesend_udp_collected(stream_int)) {
			sleepFlag = false;
			continue;
		}

		if (stream_int->int_recv_buffer_used &&
		    stream_int->tp_sent_count < RAMP_PID_QUEUE_SIZE) {
			sleepFlag = false;
			//pthread_mutex_lock(&stream->mutex);

			int offset = 0;
			int count = 0;

			while (offset < stream_int->int_recv_buffer_used) {
				struct ramp_packet_int *pkt =
					ramp_alloc_udp_packet(
						stream_int, stream_int->tp_pid,
						0);

#ifdef _WIN32
				EnterCriticalSection(&stream_int->critsec);
#else
				pthread_mutex_lock(&stream_int->mutex);
#endif

				pkt->data_used =
					min(stream_int->int_recv_buffer_used -
						    offset,
					    min(stream_int->tp_size,
						pkt->data_size));
				memcpy(&pkt->data,
				       stream_int->int_recv_buffer + offset,
				       pkt->data_used);

#ifdef _WIN32
				LeaveCriticalSection(
					(LPCRITICAL_SECTION)&stream_int
						->critsec);
#else
				pthread_mutex_unlock(&stream_int->mutex);
#endif

				if (!ramp_send_udp_packet(stream_int, pkt,
							  true))
					break;

				if (stream_int->tp_pid)
					stream_int->tp_pid++;

				offset += pkt->data_used;
				stream_int->stat_pkt_sent_regular++;
				stream_int->sent_any_after_confirm = true;

				count++;
			}

			if (offset) {
#ifdef _WIN32
				EnterCriticalSection(&stream_int->critsec);
#else
				pthread_mutex_lock(&stream_int->mutex);
#endif

				if (offset < stream_int->int_recv_buffer_used) {
					memmove(stream_int->int_recv_buffer,
						stream_int->int_recv_buffer +
							offset,
						stream_int->int_recv_buffer_used -
							offset);
					stream_int->int_recv_buffer_used -=
						offset;
				} else
					stream_int->int_recv_buffer_used = 0;

#ifdef _WIN32
				LeaveCriticalSection(&stream_int->critsec);
#else
				pthread_mutex_unlock(&stream_int->mutex);
#endif
			}
		}
	}

	debug("Work thread stop");

#ifdef _WIN32
	return 0;
#else
	return NULL;
#endif
}

// Output integration functions

bool ramp_send_meta(ramp_stream_int *stream_int, int index, char *codec,
		    int width, int height, int bitrate, double framerate,
		    char *audio_codec, long audio_bitrate, int audio_samplerate,
		    int audio_samplesize, int audio_channels, char *encoder)
{

	if (!stream_int)
		return false;
	/*
	#ifdef _WIN32
	EnterCriticalSection(&stream_int->critsec);
	#else
	pthread_mutex_lock(&stream_int->mutex);
	#endif
	*/
	if (!stream_int->alive || !stream_int->rtmp) {
		/*
		#ifdef _WIN32
		LeaveCriticalSection(&stream_int->critsec);
		#else
		pthread_mutex_unlock(&stream_int->mutex);
		#endif
		*/
		return false;
	}

	char buf[4096];
	char *enc = buf + 11;
	char *end = enc + sizeof(buf) - 11 - 4;

	memset(buf, 0, sizeof(buf));

	enc_str(&enc, end, "onMetaData");
	*enc++ = AMF_ECMA_ARRAY;
	enc = AMF_EncodeInt32(enc, end, index == 0 ? 20 : 15);

	enc_num_val(&enc, end, "duration", 0.0);
	enc_num_val(&enc, end, "fileSize", 0.0);

	if (!index) {
		enc_num_val(&enc, end, "width", (double)width);
		enc_num_val(&enc, end, "height", (double)height);

		enc_str_val(&enc, end, "videocodecid", codec);
		enc_num_val(&enc, end, "videodatarate", bitrate);
		enc_num_val(&enc, end, "framerate", framerate);
	}

	enc_str_val(&enc, end, "audiocodecid", audio_codec);
	enc_num_val(&enc, end, "audiodatarate", audio_bitrate);
	enc_num_val(&enc, end, "audiosamplerate", audio_samplerate);
	enc_num_val(&enc, end, "audiosamplesize", audio_samplesize);
	enc_num_val(&enc, end, "audiochannels", audio_channels);

	enc_bool_val(&enc, end, "stereo", audio_channels == 2);
	enc_bool_val(&enc, end, "2.1", audio_channels == 3);
	enc_bool_val(&enc, end, "3.1", audio_channels == 4);
	enc_bool_val(&enc, end, "4.0", audio_channels == 4);
	enc_bool_val(&enc, end, "4.1", audio_channels == 5);
	enc_bool_val(&enc, end, "5.1", audio_channels == 6);
	enc_bool_val(&enc, end, "7.1", audio_channels == 8);

	enc_str_val(&enc, end, "encoder", encoder);

	*enc++ = 0;
	*enc++ = 0;
	*enc++ = AMF_OBJECT_END;

	int pos = enc - buf;
	int size = pos - 11;

	buf[0] = RTMP_PACKET_TYPE_INFO;
	buf[1] = (size >> 16) & 0xFF;
	buf[2] = (size >> 8) & 0xFF;
	buf[3] = size & 0xFF;

	size += 11 - 1;
	buf[pos] = (size >> 24) & 0xFF;
	buf[pos + 1] = (size >> 16) & 0xFF;
	buf[pos + 2] = (size >> 8) & 0xFF;
	buf[pos + 3] = size & 0xFF;
	pos += 4;

	int res = RTMP_Write(stream_int->rtmp, buf, pos, index) >= 0;

	/*
	#ifdef _WIN32
	LeaveCriticalSection(&stream_int->critsec);
	#else
	pthread_mutex_unlock(&stream_int->mutex);
	#endif
	*/

	return res;
}

int ramp_send_video(ramp_stream_int *stream_int, int index, bool header,
		    bool keyframe, int32_t timestamp, int32_t pts_offset,
		    void *data, int size)
{
	if (!stream_int)
		return -1;
	/*
	#ifdef _WIN32
	EnterCriticalSection(&stream_int->critsec);
	#else
	pthread_mutex_lock(&stream_int->mutex);
	#endif
	*/
	if (!stream_int->alive || !stream_int->rtmp || !data || size < 1) {
		/*
		#ifdef _WIN32
		LeaveCriticalSection(&stream_int->critsec);
		#else
		pthread_mutex_unlock(&stream_int->mutex);
		#endif
		*/
		return 0;
	}

	char *buf = malloc(size + 20);
	if (!buf) {
		/*
		#ifdef _WIN32
		LeaveCriticalSection(&stream_int->critsec);
		#else
		pthread_mutex_unlock(&stream_int->mutex);
		#endif
		*/
		return -1;
	}

	buf[0] = RTMP_PACKET_TYPE_VIDEO;
	buf[1] = ((size + 5) >> 16) & 0xFF;
	buf[2] = ((size + 5) >> 8) & 0xFF;
	buf[3] = (size + 5) & 0xFF;

	buf[4] = (timestamp >> 16) & 0xFF;
	buf[5] = (timestamp >> 8) & 0xFF;
	buf[6] = timestamp & 0xFF;
	buf[7] = (timestamp >> 24) & 0x7F;
	buf[8] = 0;
	buf[9] = 0;
	buf[10] = 0;

	buf[11] = keyframe ? 0x17 : 0x27;
	buf[12] = header ? 0 : 1;

	buf[13] = (pts_offset >> 16) & 0xFF;
	buf[14] = (pts_offset >> 8) & 0xFF;
	buf[15] = pts_offset & 0xFF;

	memcpy(buf + 16, data, size);

	int pos = size + 16;
	size += 16 - 1;

	buf[pos] = (size >> 24) & 0xFF;
	buf[pos + 1] = (size >> 16) & 0xFF;
	buf[pos + 2] = (size >> 8) & 0xFF;
	buf[pos + 3] = size & 0xFF;
	pos += 4;

	int ret = RTMP_Write(stream_int->rtmp, buf, pos, index);
	free(buf);

	/*
	#ifdef _WIN32
	LeaveCriticalSection(&stream_int->critsec);
	#else
	pthread_mutex_unlock(&stream_int->mutex);
	#endif
	*/

	return ret;
}

int ramp_send_audio(ramp_stream_int *stream_int, int index, bool header,
		    int32_t timestamp, void *data, int size)
{
	if (!stream_int)
		return -1;

	/*
	#ifdef _WIN32
	EnterCriticalSection(&stream_int->critsec);
	#else
	pthread_mutex_lock(&stream_int->mutex);
	#endif
	*/

	if (!stream_int->alive || !stream_int->rtmp || !data || size < 1) {
		/*
		#ifdef _WIN32
		LeaveCriticalSection(&stream_int->critsec);
		#else
		pthread_mutex_unlock(&stream_int->mutex);
		#endif
		*/
		return 0;
	}

	char *buf = malloc(size + 17);
	if (!buf) {
		/*
		#ifdef _WIN32
		LeaveCriticalSection(&stream_int->critsec);
		#else
		pthread_mutex_unlock(&stream_int->mutex);
		#endif
		*/
		return -1;
	}

	buf[0] = RTMP_PACKET_TYPE_AUDIO;
	buf[1] = ((size + 2) >> 16) & 0xFF;
	buf[2] = ((size + 2) >> 8) & 0xFF;
	buf[3] = (size + 2) & 0xFF;

	buf[4] = (timestamp >> 16) & 0xFF;
	buf[5] = (timestamp >> 8) & 0xFF;
	buf[6] = timestamp & 0xFF;
	buf[7] = (timestamp >> 24) & 0x7F;
	buf[8] = 0;
	buf[9] = 0;
	buf[10] = 0;

	buf[11] = 0xAF;
	buf[12] = header ? 0 : 1;

	memcpy(buf + 13, data, size);

	int pos = size + 13;
	size += 13 - 1;

	buf[pos] = (size >> 24) & 0xFF;
	buf[pos + 1] = (size >> 16) & 0xFF;
	buf[pos + 2] = (size >> 8) & 0xFF;
	buf[pos + 3] = size & 0xFF;
	pos += 4;

	int ret = RTMP_Write(stream_int->rtmp, buf, pos, index);
	free(buf);

	/*
	#ifdef _WIN32
	LeaveCriticalSection(&stream_int->critsec);
	#else
	pthread_mutex_unlock(&stream_int->mutex);
	#endif
	*/

	return ret;
}

int ramp_rtmp_custom_connect(RTMP *r, struct sockaddr *addr, socklen_t addrlen,
			     void *param)
{
	ramp_stream_int *stream_int = (ramp_stream_int *)param;
	if (!stream_int || !stream_int->alive)
		return FALSE;

	return TRUE;
}

int ramp_rtmp_custom_is_connected(RTMP *r, void *param)
{
	ramp_stream_int *stream_int = (ramp_stream_int *)param;
	if (!stream_int || !stream_int->alive)
		return FALSE;

	return TRUE;
}

int ramp_rtmp_custom_send(RTMPSockBuf *sock_buf, const char *buffer, int size,
			  void *param)
{
	ramp_stream_int *stream_int = (ramp_stream_int *)param;
	if (!stream_int || !stream_int->alive ||
	    size > stream_int->int_recv_buffer_size)
		return -1;

	while (true) {
		if (!stream_int->alive)
			return -1;

		//TODO Add max waiting time
		if (!sock_buf ||
		    size <= stream_int->int_recv_buffer_size -
				    stream_int->int_recv_buffer_used)
			break;

		msleep(1);
	}

#ifdef _WIN32
	EnterCriticalSection(&stream_int->critsec);
#else
	pthread_mutex_lock(&stream_int->mutex);
#endif

	//TODO Check if 0 is correct and sender will retry
	if (size < 1 || size > stream_int->int_recv_buffer_size -
					stream_int->int_recv_buffer_used) {
#ifdef _WIN32
		LeaveCriticalSection(&stream_int->critsec);
#else
		pthread_mutex_unlock(&stream_int->mutex);
#endif

		return 0;
	}

	memcpy(stream_int->int_recv_buffer + stream_int->int_recv_buffer_used,
	       buffer, size);
	stream_int->int_recv_buffer_used += size;

#ifdef _WIN32
	LeaveCriticalSection(&stream_int->critsec);
#else
	pthread_mutex_unlock(&stream_int->mutex);
#endif

	return size;
}

int ramp_rtmp_custom_recv(RTMPSockBuf *sock_buf, const char *buffer, int size,
			  void *param)
{
	ramp_stream_int *stream_int = (ramp_stream_int *)param;
	if (!stream_int)
		return -1;

	while (true) {
		if (!stream_int->alive)
			return -1;

		//TODO Add max waiting time
		if (!sock_buf || stream_int->int_send_buffer_used)
			break;

		msleep(1);
	}

#ifdef _WIN32
	EnterCriticalSection(&stream_int->critsec);
#else
	pthread_mutex_lock(&stream_int->mutex);
#endif

	if (size < 1 || !stream_int->int_send_buffer_used) {
#ifdef _WIN32
		LeaveCriticalSection(&stream_int->critsec);
#else
		pthread_mutex_unlock(&stream_int->mutex);
#endif
		return 0;
	}

	int res_size = min(size, stream_int->int_send_buffer_used);
	memcpy(buffer, stream_int->int_send_buffer, res_size);

	if (res_size < stream_int->int_send_buffer_used)
		memmove(stream_int->int_send_buffer,
			stream_int->int_send_buffer + res_size,
			stream_int->int_send_buffer_used - res_size);

	stream_int->int_send_buffer_used -= res_size;

#ifdef _WIN32
	LeaveCriticalSection(&stream_int->critsec);
#else
	pthread_mutex_unlock(&stream_int->mutex);
#endif

	return res_size;
}

//bool ramp_isalive(ramp_stream_int *stream_int)
//{
//	return stream_int && stream_int->alive;
//}

void ramp_disconnect(ramp_stream_int *stream_int)
{
	if (stream_int) {
		if (stream_int->rtmp)
			RTMP_Close(stream_int->rtmp);

		for (int i = 0; i < 200; i++) {
			if (!stream_int->int_recv_buffer_used)
				break;

			msleep(1);
		}

		stream_int->alive = false;
	}
}

void ramp_stop(ramp_stream_int **param)
{
	if (!param)
		return;

	//TODO thread sync?

	ramp_stream_int *stream_int = *param;
	if (!stream_int)
		return;

#ifdef _WIN32
	EnterCriticalSection(&stream_int->critsec);
#else
	pthread_mutex_lock(&stream_int->mutex);
#endif

	ramp_disconnect(stream_int);

	if (stream_int->rtmp) {
		free(stream_int->rtmp);
		stream_int->rtmp = NULL;
	}

#ifdef _WIN32
	LeaveCriticalSection(&stream_int->critsec);
#else
	pthread_mutex_unlock(&stream_int->mutex);
#endif

	//if(stream_int->alive) {
	//    stream_int->alive = false;

#ifdef _WIN32
	WaitForSingleObject(stream_int->thread, INFINITE);
	CloseHandle(stream_int->thread);
	stream_int->thread = NULL;
#else
	pthread_join(stream_int->thread, NULL);
#endif

	struct ramp_packet_int *pkt = ramp_alloc_udp_packet(stream_int, 3, 0);
	ramp_send_udp_packet(stream_int, pkt, false);
	//}

#ifdef _WIN32
	DeleteCriticalSection(&stream_int->critsec);
#else
	pthread_mutex_destroy(&stream_int->mutex);
#endif

	if (stream_int->int_recv_buffer) {
		free(stream_int->int_recv_buffer);
		stream_int->int_recv_buffer = NULL;
	}

	if (stream_int->int_send_buffer) {
		free(stream_int->int_send_buffer);
		stream_int->int_send_buffer = NULL;
	}

	if (stream_int->ext_recv_buffer) {
		free(stream_int->ext_recv_buffer);
		stream_int->ext_recv_buffer = NULL;
	}

	while (stream_int->tp_sent_first) {
		struct ramp_packet_int *next = stream_int->tp_sent_first->next;
		free(stream_int->tp_sent_first);
		stream_int->tp_sent_first = next;
	}

	if (stream_int->ext_socket) {
#ifdef _WIN32
		closesocket(stream_int->ext_socket);
#else
		close(stream_int->ext_socket);
#endif

		stream_int->ext_socket = 0;
	}

	free(stream_int);
	*param = NULL;

	info("Stop");
}

ramp_stream_int *ramp_start(const char *url, const char *key,
			    const char *username, const char *password)
{

	info("Start, url=%s", url);

	ramp_stream_int *stream_int = malloc(sizeof(ramp_stream_int));
	if (!stream_int)
		return false;

	memset(stream_int, 0, sizeof(ramp_stream_int));

	stream_int->rtmp = malloc(sizeof(RTMP));
	if (!stream_int->rtmp) {
		ramp_stop(&stream_int);
		return NULL;
	}

	memset(stream_int->rtmp, 0, sizeof(RTMP));

	// Rtmp init part
	RTMP_Init(stream_int->rtmp);
	RTMP_SetupURL(stream_int->rtmp, "rtmp://127.0.0.1/live");
	RTMP_EnableWrite(stream_int->rtmp);

	stream_int->encoder_name = strdup("FMLE/3.0 (compatible; FMSc/1.0)");

	set_aval(&stream_int->rtmp->Link.pubUser, username);
	set_aval(&stream_int->rtmp->Link.pubPasswd, password);
	set_aval(&stream_int->rtmp->Link.flashVer, stream_int->encoder_name);
	stream_int->rtmp->Link.swfUrl = stream_int->rtmp->Link.tcUrl;

	RTMP_AddStream(stream_int->rtmp, key);

	/*
	for (size_t idx = 1;; idx++) {
	obs_encoder_t *encoder =
	obs_output_get_audio_encoder(stream->output, idx);
	const char *encoder_name;

	if (!encoder)
	break;

	encoder_name = obs_encoder_get_name(encoder);
	RAMP_AddStream(&stream->rtmp, encoder_name);
	}
	*/
	stream_int->rtmp->m_outChunkSize = 4096;
	stream_int->rtmp->m_bSendChunkSizeInfo = true;

	//TODO check it
	stream_int->rtmp->m_bUseNagle = false; // true

	/*
	#ifdef _WIN32
	win32_log_interface_type(stream_int);
	#endif
	*/

	// Tunnel init part
	stream_int->ext_udp_addr = strdup(url);

	char *port_str = strchr(stream_int->ext_udp_addr, ':');
	if (port_str) {
		*port_str = 0;
		port_str++;

		char *port_str2 = strchr(port_str, ':');
		if (port_str2) {
			*port_str2 = 0;
			*port_str2++;

			stream_int->int_udp_port = atoi(port_str2);
		}

		stream_int->ext_udp_port = atoi(port_str);
	}

	stream_int->ext_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (stream_int->ext_socket < 0)
		return false;

	int send_size;
	socklen_t send_size_size = sizeof(send_size);
	int res = getsockopt(stream_int->ext_socket, SOL_SOCKET, SO_RCVBUF,
			     (char *)&send_size, &send_size_size);

#ifdef _WIN32
	if (res != NO_ERROR) {
#else
	if (res < 0) {
#endif
		ramp_stop(&stream_int);
		return NULL;
	}

	send_size *= 4;
	send_size_size = sizeof(send_size);
	setsockopt(stream_int->ext_socket, SOL_SOCKET, SO_RCVBUF,
		   (const char *)&send_size, send_size_size);

#ifdef _WIN32
	u_long mode = 1;
	res = ioctlsocket(stream_int->ext_socket, FIONBIO, &mode);
	if (res != NO_ERROR) {
		ramp_stop(&stream_int);
		return NULL;
	}
#else
	if (fcntl(stream_int->ext_socket, F_SETFL,
		  fcntl(stream_int->ext_socket, F_GETFL) | O_NONBLOCK) < 0)
		return false;
#endif

	struct sockaddr_in ext_int_addr;
	memset(&ext_int_addr, 0, sizeof(ext_int_addr));

	ext_int_addr.sin_family = AF_INET;
	ext_int_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ext_int_addr.sin_port = htons(stream_int->int_udp_port);

	if (bind(stream_int->ext_socket, (struct sockaddr *)&ext_int_addr,
		 sizeof(ext_int_addr)) < 0) {
		ramp_stop(&stream_int);
		return false;
	}

	socklen_t ext_int_addr_len = sizeof(ext_int_addr);
	getsockname(stream_int->ext_socket, (struct sockaddr *)&ext_int_addr,
		    &ext_int_addr_len);
	stream_int->int_udp_port = ntohs(ext_int_addr.sin_port);

	stream_int->tp_pid = 100;
	stream_int->tp_size = 1400;
	stream_int->tp_recv_pid = 99;

	srand((unsigned int)time(NULL));
	int remote_channel = rand() % 8;

	info("Internal port=%d, external addresses:port=%s:%d (%d)",
	     stream_int->int_udp_port, stream_int->ext_udp_addr,
	     stream_int->ext_udp_port + remote_channel,
	     stream_int->ext_udp_port + remote_channel + 10);

	stream_int->int_recv_buffer_size = 0x10000;
	stream_int->int_recv_buffer = malloc(stream_int->int_recv_buffer_size);

	stream_int->int_send_buffer_size = 0x10000;
	stream_int->int_send_buffer = malloc(stream_int->int_send_buffer_size);

	stream_int->ext_recv_buffer_size = 5600 + 100;
	stream_int->ext_recv_buffer = malloc(stream_int->ext_recv_buffer_size);

	stream_int->ext_to.sin_family = AF_INET;
	stream_int->ext_to.sin_addr.s_addr =
		inet_addr(stream_int->ext_udp_addr);

	stream_int->ext_to10.sin_family = AF_INET;
	stream_int->ext_to10.sin_addr.s_addr =
		inet_addr(stream_int->ext_udp_addr);

	for (int i = 0; i < 256; i++)
		stream_int->c_key[i] = rand();

	info("Encryption=enabled, key len=256");

	if (stream_int->ext_to.sin_addr.s_addr == INADDR_NONE) {
		struct hostent *hp = gethostbyname(stream_int->ext_udp_addr);
		if (!hp || !hp->h_addr) {
			RTMP_Log(RTMP_LOGCRIT, "Can't resolve host address: %s",
				 stream_int->ext_udp_addr);
			ramp_stop(&stream_int);
			return NULL;
		} else {
			stream_int->ext_to.sin_addr =
				*(struct in_addr *)hp->h_addr;
			stream_int->ext_to10.sin_addr =
				*(struct in_addr *)hp->h_addr;

			unsigned char *addrBytes =
				(unsigned char *)&stream_int->ext_to.sin_addr;
			debug("Remote address=%d.%d.%d.%d", (int)addrBytes[0],
			      (int)addrBytes[1], (int)addrBytes[2],
			      addrBytes[3]);
		}
	}

	stream_int->ext_to.sin_port =
		htons(stream_int->ext_udp_port + remote_channel);
	stream_int->ext_to10.sin_port =
		htons(stream_int->ext_udp_port + remote_channel + 10);

	FD_ZERO(&stream_int->ext_socket_wset);
	FD_SET(stream_int->ext_socket, &stream_int->ext_socket_wset);

	stream_int->alive = true;

#ifdef _WIN32
	InitializeCriticalSection(&stream_int->critsec);
	stream_int->thread =
		CreateThread(NULL, 0, ramp_thread, stream_int, 0, NULL);
#else
	pthread_mutex_init(&stream_int->mutex, NULL);
	pthread_create(&stream_int->thread, NULL, ramp_thread, stream_int);
#endif

	stream_int->rtmp->m_bCustomConnect = 1;
	stream_int->rtmp->m_customConnectParam = stream_int;
	stream_int->rtmp->m_customConnectFunc = ramp_rtmp_custom_connect;

	stream_int->rtmp->m_bCustomIsConnected = 1;
	stream_int->rtmp->m_customIsConnectedParam = stream_int;
	stream_int->rtmp->m_customIsConnectedFunc =
		ramp_rtmp_custom_is_connected;

	stream_int->rtmp->m_bCustomRecv = 1;
	stream_int->rtmp->m_customRecvParam = stream_int;
	stream_int->rtmp->m_customRecvFunc = ramp_rtmp_custom_recv;

	stream_int->rtmp->m_bCustomSend = 1;
	stream_int->rtmp->m_customSendParam = stream_int;
	stream_int->rtmp->m_customSendFunc = ramp_rtmp_custom_send;

	//TODO Support recv custom func
	//stream_int->rtmp->recvFunc = ramp_receive;

	if (!RTMP_Connect(stream_int->rtmp, NULL)) {
		ramp_stop(&stream_int);
		//set_output_error(stream);
		return NULL;
	}

	if (!RTMP_ConnectStream(stream_int->rtmp, 0)) {
		ramp_stop(&stream_int);
		return NULL;
	}

	info("Connection to %s successful", url);
	return stream_int;
}

#ifndef SEC_TO_NSEC
#define SEC_TO_NSEC 1000000000ULL
#endif

#ifndef MSEC_TO_USEC
#define MSEC_TO_USEC 1000ULL
#endif

#ifndef MSEC_TO_NSEC
#define MSEC_TO_NSEC 1000000ULL
#endif

/* dynamic bitrate coefficients */
#define DBR_INC_TIMER (30ULL * SEC_TO_NSEC)
#define DBR_TRIGGER_USEC (200ULL * MSEC_TO_USEC)
#define MIN_ESTIMATE_DURATION_MS 1000
#define MAX_ESTIMATE_DURATION_MS 2000

static const char *ramp_stream_getname(void *unused)
{
	UNUSED_PARAMETER(unused);
	return obs_module_text("RAMP");
}

static inline size_t num_buffered_packets(struct ramp_stream *stream);

static inline void free_packets(struct ramp_stream *stream)
{
	size_t num_packets;

	pthread_mutex_lock(&stream->packets_mutex);

	num_packets = num_buffered_packets(stream);
	//if (num_packets)
	//	info("Freeing %d remaining packets", (int)num_packets);

	while (stream->packets.size) {
		struct encoder_packet packet;
		circlebuf_pop_front(&stream->packets, &packet, sizeof(packet));
		obs_encoder_packet_release(&packet);
	}
	pthread_mutex_unlock(&stream->packets_mutex);
}

static inline bool stopping(struct ramp_stream *stream)
{
	return os_event_try(stream->stop_event) != EAGAIN;
}

static inline bool connecting(struct ramp_stream *stream)
{
	return os_atomic_load_bool(&stream->connecting);
}

static inline bool active(struct ramp_stream *stream)
{
	return os_atomic_load_bool(&stream->active);
}

static inline bool disconnected(struct ramp_stream *stream)
{
	return os_atomic_load_bool(&stream->disconnected);
}

static void ramp_stream_destroy(void *param)
{
	struct ramp_stream *stream = param;
	obs_output_end_data_capture(stream->output);

	free_packets(stream);
	os_event_destroy(stream->stop_event);
	os_sem_destroy(stream->send_sem);
	pthread_mutex_destroy(&stream->packets_mutex);
	circlebuf_free(&stream->packets);

#ifdef TEST_FRAMEDROPS
	circlebuf_free(&stream->droptest_info);
#endif

	circlebuf_free(&stream->dbr_frames);
	pthread_mutex_destroy(&stream->dbr_mutex);

	os_event_destroy(stream->buffer_space_available_event);
	os_event_destroy(stream->buffer_has_data_event);
	os_event_destroy(stream->socket_available_event);
	os_event_destroy(stream->send_thread_signaled_exit);
	pthread_mutex_destroy(&stream->write_buf_mutex);

	if (stream->write_buf)
		bfree(stream->write_buf);

	bfree(stream);
}

static void *ramp_stream_create(obs_data_t *settings, obs_output_t *output)
{
	struct ramp_stream *stream = bzalloc(sizeof(struct ramp_stream));
	stream->output = output;
	pthread_mutex_init_value(&stream->packets_mutex);

	if (pthread_mutex_init(&stream->packets_mutex, NULL) != 0)
		goto fail;
	if (os_event_init(&stream->stop_event, OS_EVENT_TYPE_MANUAL) != 0)
		goto fail;

	if (pthread_mutex_init(&stream->write_buf_mutex, NULL) != 0) {
		warn("Failed to initialize write buffer mutex");
		goto fail;
	}

	if (pthread_mutex_init(&stream->dbr_mutex, NULL) != 0) {
		warn("Failed to initialize dbr mutex");
		goto fail;
	}

	if (os_event_init(&stream->buffer_space_available_event,
			  OS_EVENT_TYPE_AUTO) != 0) {
		warn("Failed to initialize write buffer event");
		goto fail;
	}
	if (os_event_init(&stream->buffer_has_data_event, OS_EVENT_TYPE_AUTO) !=
	    0) {
		warn("Failed to initialize data buffer event");
		goto fail;
	}
	if (os_event_init(&stream->socket_available_event,
			  OS_EVENT_TYPE_AUTO) != 0) {
		warn("Failed to initialize socket buffer event");
		goto fail;
	}
	if (os_event_init(&stream->send_thread_signaled_exit,
			  OS_EVENT_TYPE_MANUAL) != 0) {
		warn("Failed to initialize socket exit event");
		goto fail;
	}

	UNUSED_PARAMETER(settings);
	return stream;

fail:
	ramp_stream_destroy(stream);
	return NULL;
}

static void ramp_stream_stop(void *data, uint64_t ts)
{
	struct ramp_stream *stream = data;

	stream->stop_ts = ts / 1000ULL;

	if (ts)
		stream->shutdown_timeout_ts =
			ts +
			(uint64_t)stream->max_shutdown_time_sec * 1000000000ULL;

	ramp_disconnect(stream->stream_int);

	if (connecting(stream))
		pthread_join(stream->connect_thread, NULL);

	if (active(stream)) {
		os_event_signal(stream->stop_event);
		os_sem_post(stream->send_sem);
		pthread_join(stream->send_thread, NULL);
	} else
		obs_output_signal_stop(stream->output, OBS_OUTPUT_SUCCESS);

	ramp_stop(&stream->stream_int);
}

static inline void set_ramp_str(AVal *val, const char *str)
{
	bool valid = (str && *str);
	val->av_val = valid ? (char *)str : NULL;
	val->av_len = valid ? (int)strlen(str) : 0;
}

static inline void set_ramp_dstr(AVal *val, struct dstr *str)
{
	bool valid = !dstr_is_empty(str);
	val->av_val = valid ? str->array : NULL;
	val->av_len = valid ? (int)str->len : 0;
}

static inline bool get_next_packet(struct ramp_stream *stream,
				   struct encoder_packet *packet)
{
	bool new_packet = false;

	pthread_mutex_lock(&stream->packets_mutex);
	if (stream->packets.size) {
		circlebuf_pop_front(&stream->packets, packet,
				    sizeof(struct encoder_packet));
		new_packet = true;
	}
	pthread_mutex_unlock(&stream->packets_mutex);

	return new_packet;
}

static int send_packet(struct ramp_stream *stream,
		       struct encoder_packet *packet, bool is_header,
		       size_t idx)
{
	if (!stream->stream_int)
		return -1;

	size_t size;
	int ret = 0;
	char buf[8192];

	while (true) {
		ret = ramp_rtmp_custom_recv(NULL, buf, sizeof(buf),
					    stream->stream_int);
		if (ret < 0)
			return -1;
		if (!ret)
			break;
	}

	if (packet->type == OBS_ENCODER_VIDEO) {
		int32_t timestamp = get_ms_time(packet, packet->dts) -
				    (is_header ? 0 : stream->start_dts_offset);
		int32_t pts_offset =
			get_ms_time(packet, packet->pts - packet->dts);
		ret = ramp_send_video(stream->stream_int, (int)idx, is_header,
				      packet->keyframe, timestamp, pts_offset,
				      packet->data, (int)packet->size);
		size = ret >= 0 ? ret : 0;
	} else {
		int32_t timestamp = get_ms_time(packet, packet->dts) -
				    (is_header ? 0 : stream->start_dts_offset);
		ret = ramp_send_audio(stream->stream_int, (int)idx, is_header,
				      timestamp, packet->data,
				      (int)packet->size);
		size = ret >= 0 ? ret : 0;
	}

	if (is_header)
		bfree(packet->data);
	else
		obs_encoder_packet_release(packet);

	stream->total_bytes_sent += size;
	return ret;
}

static inline bool send_headers(struct ramp_stream *stream);

static inline bool can_shutdown_stream(struct ramp_stream *stream,
				       struct encoder_packet *packet)
{
	uint64_t cur_time = os_gettime_ns();
	bool timeout = cur_time >= stream->shutdown_timeout_ts;

	if (timeout)
		info("Stream shutdown timeout reached (%d second(s))",
		     stream->max_shutdown_time_sec);

	return timeout || packet->sys_dts_usec >= (int64_t)stream->stop_ts;
}

static void set_output_error(struct ramp_stream *stream)
{
	const char *msg = NULL;
	if (stream->stream_int && stream->stream_int->rtmp) {
#ifdef _WIN32
		switch (stream->stream_int->rtmp->last_error_code) {
		case WSAETIMEDOUT:
			msg = obs_module_text("ConnectionTimedOut");
			break;
		case WSAEACCES:
			msg = obs_module_text("PermissionDenied");
			break;
		case WSAECONNABORTED:
			msg = obs_module_text("ConnectionAborted");
			break;
		case WSAECONNRESET:
			msg = obs_module_text("ConnectionReset");
			break;
		case WSAHOST_NOT_FOUND:
			msg = obs_module_text("HostNotFound");
			break;
		case WSANO_DATA:
			msg = obs_module_text("NoData");
			break;
		case WSAEADDRNOTAVAIL:
			msg = obs_module_text("AddressNotAvailable");
			break;
		}
#else
		switch (stream->stream_int->rtmp->last_error_code) {
		case ETIMEDOUT:
			msg = obs_module_text("ConnectionTimedOut");
			break;
		case EACCES:
			msg = obs_module_text("PermissionDenied");
			break;
		case ECONNABORTED:
			msg = obs_module_text("ConnectionAborted");
			break;
		case ECONNRESET:
			msg = obs_module_text("ConnectionReset");
			break;
		case HOST_NOT_FOUND:
			msg = obs_module_text("HostNotFound");
			break;
		case NO_DATA:
			msg = obs_module_text("NoData");
			break;
		case EADDRNOTAVAIL:
			msg = obs_module_text("AddressNotAvailable");
			break;
		}
#endif
	}

	obs_output_set_last_error(stream->output, msg);
}

static void dbr_add_frame(struct ramp_stream *stream, struct dbr_frame *back)
{
	struct dbr_frame front;
	uint64_t dur;

	circlebuf_push_back(&stream->dbr_frames, back, sizeof(*back));
	circlebuf_peek_front(&stream->dbr_frames, &front, sizeof(front));

	stream->dbr_data_size += back->size;

	dur = (back->send_end - front.send_beg) / 1000000;

	if (dur >= MAX_ESTIMATE_DURATION_MS) {
		stream->dbr_data_size -= front.size;
		circlebuf_pop_front(&stream->dbr_frames, NULL, sizeof(front));
	}

	stream->dbr_est_bitrate =
		(dur >= MIN_ESTIMATE_DURATION_MS)
			? (long)(stream->dbr_data_size * 1000 / dur)
			: 0;
	stream->dbr_est_bitrate *= 8;
	stream->dbr_est_bitrate /= 1000;

	if (stream->dbr_est_bitrate) {
		stream->dbr_est_bitrate -= stream->audio_bitrate;
		if (stream->dbr_est_bitrate < 50)
			stream->dbr_est_bitrate = 50;
	}
}

static void dbr_set_bitrate(struct ramp_stream *stream);

static void *send_thread(void *data)
{
	struct ramp_stream *stream = data;

	os_set_thread_name("ramp: send_thread");

	while (os_sem_wait(stream->send_sem) == 0) {
		struct encoder_packet packet;
		struct dbr_frame dbr_frame;

		if (stopping(stream) && stream->stop_ts == 0) {
			break;
		}

		if (!get_next_packet(stream, &packet))
			continue;

		if (stopping(stream)) {
			if (can_shutdown_stream(stream, &packet)) {
				obs_encoder_packet_release(&packet);
				break;
			}
		}

		if (!stream->sent_headers) {
			if (!send_headers(stream)) {
				os_atomic_set_bool(&stream->disconnected, true);
				break;
			}
		}

		if (stream->dbr_enabled) {
			dbr_frame.send_beg = os_gettime_ns();
			dbr_frame.size = packet.size;
		}

		if (send_packet(stream, &packet, false, packet.track_idx) < 0) {
			os_atomic_set_bool(&stream->disconnected, true);
			break;
		}

		if (stream->dbr_enabled) {
			dbr_frame.send_end = os_gettime_ns();

			pthread_mutex_lock(&stream->dbr_mutex);
			dbr_add_frame(stream, &dbr_frame);
			pthread_mutex_unlock(&stream->dbr_mutex);
		}
	}

	bool encode_error = os_atomic_load_bool(&stream->encode_error);

	if (disconnected(stream)) {
		info("Disconnected");
	} else if (encode_error) {
		info("Encoder error, disconnecting");
	} else {
		info("User stopped the stream");
	}

	set_output_error(stream);
	//RAMP_Close(stream->sdk->rtmp);

	if (!stopping(stream)) {
		pthread_detach(stream->send_thread);
		obs_output_signal_stop(stream->output, OBS_OUTPUT_DISCONNECTED);
	} else if (encode_error) {
		obs_output_signal_stop(stream->output, OBS_OUTPUT_ENCODE_ERROR);
	} else {
		obs_output_end_data_capture(stream->output);
	}

	free_packets(stream);
	os_event_reset(stream->stop_event);
	os_atomic_set_bool(&stream->active, false);
	stream->sent_headers = false;

	/* reset bitrate on stop */
	if (stream->dbr_enabled) {
		if (stream->dbr_cur_bitrate != stream->dbr_orig_bitrate) {
			stream->dbr_cur_bitrate = stream->dbr_orig_bitrate;
			dbr_set_bitrate(stream);
		}
	}

	return NULL;
}

static inline double encoder_bitrate(obs_encoder_t *encoder)
{
	obs_data_t *settings = obs_encoder_get_settings(encoder);
	double bitrate = obs_data_get_double(settings, "bitrate");

	obs_data_release(settings);
	return bitrate;
}

static bool send_meta_data(struct ramp_stream *stream, size_t idx, bool *next)
{
	bool success = true;

	obs_encoder_t *vencoder = obs_output_get_video_encoder(stream->output);
	obs_encoder_t *aencoder =
		obs_output_get_audio_encoder(stream->output, idx);
	video_t *video = obs_encoder_video(vencoder);
	audio_t *audio = obs_encoder_audio(aencoder);

	if (idx > 0 && !aencoder) {
		*next = false;
		return true;
	}

	struct dstr encoder_name = {0};
	dstr_printf(&encoder_name, "%s (libobs version ", MODULE_NAME);

#ifdef HAVE_OBSCONFIG_H
	dstr_cat(&encoder_name, OBS_VERSION);
#else
	dstr_catf(&encoder_name, "%d.%d.%d", LIBOBS_API_MAJOR_VER,
		  LIBOBS_API_MINOR_VER, LIBOBS_API_PATCH_VER);
#endif

	dstr_cat(&encoder_name, ")");

	ramp_send_meta(stream->stream_int, (int)idx, "avc1",
		       obs_encoder_get_width(vencoder),
		       obs_encoder_get_height(vencoder),
		       encoder_bitrate(vencoder),
		       video_output_get_frame_rate(video), "mp4a",
		       encoder_bitrate(aencoder),
		       obs_encoder_get_sample_rate(aencoder), 16,
		       (int)audio_output_get_channels(audio),
		       encoder_name.array);

	dstr_free(&encoder_name);

	*next = true;
	return success;
}

static bool send_audio_header(struct ramp_stream *stream, size_t idx,
			      bool *next)
{
	obs_output_t *context = stream->output;
	obs_encoder_t *aencoder = obs_output_get_audio_encoder(context, idx);
	uint8_t *header;

	struct encoder_packet packet = {.type = OBS_ENCODER_AUDIO,
					.timebase_den = 1};

	if (!aencoder) {
		*next = false;
		return true;
	}

	obs_encoder_get_extra_data(aencoder, &header, &packet.size);
	packet.data = bmemdup(header, packet.size);
	return send_packet(stream, &packet, true, idx) >= 0;
}

static bool send_video_header(struct ramp_stream *stream)
{
	obs_output_t *context = stream->output;
	obs_encoder_t *vencoder = obs_output_get_video_encoder(context);
	uint8_t *header;
	size_t size;

	struct encoder_packet packet = {
		.type = OBS_ENCODER_VIDEO, .timebase_den = 1, .keyframe = true};

	obs_encoder_get_extra_data(vencoder, &header, &size);
	packet.size = obs_parse_avc_header(&packet.data, header, size);
	return send_packet(stream, &packet, true, 0) >= 0;
}

static inline bool send_headers(struct ramp_stream *stream)
{
	stream->sent_headers = true;
	size_t i = 0;
	bool next = true;

	if (!send_audio_header(stream, i++, &next))
		return false;
	if (!send_video_header(stream))
		return false;

	while (next) {
		if (!send_audio_header(stream, i++, &next))
			return false;
	}

	return true;
}

static inline bool reset_semaphore(struct ramp_stream *stream)
{
	os_sem_destroy(stream->send_sem);
	return os_sem_init(&stream->send_sem, 0) == 0;
}

static int init_send(struct ramp_stream *stream)
{
	int ret;
	size_t idx = 0;
	bool next = true;

	reset_semaphore(stream);
	ret = pthread_create(&stream->send_thread, NULL, send_thread, stream);
	if (ret != 0) {
		//ramp_close(stream->sdk->rtmp);
		warn("Failed to create send thread");
		return OBS_OUTPUT_ERROR;
	}

	os_atomic_set_bool(&stream->active, true);
	while (next) {
		if (!send_meta_data(stream, idx++, &next)) {
			warn("Disconnected while attempting to connect to "
			     "server.");
			set_output_error(stream);
			return OBS_OUTPUT_DISCONNECTED;
		}
	}
	obs_output_begin_data_capture(stream->output, 0);

	return OBS_OUTPUT_SUCCESS;
}

static bool init_connect(struct ramp_stream *stream)
{
	obs_service_t *service;
	obs_data_t *settings;
	//const char *bind_ip;
	int64_t drop_p;
	int64_t drop_b;
	uint32_t caps;

	if (stopping(stream)) {
		pthread_join(stream->send_thread, NULL);
	}

	free_packets(stream);

	service = obs_output_get_service(stream->output);
	if (!service)
		return false;

	os_atomic_set_bool(&stream->disconnected, false);
	os_atomic_set_bool(&stream->encode_error, false);
	stream->total_bytes_sent = 0;
	stream->dropped_frames = 0;
	stream->min_priority = 0;
	stream->got_first_video = false;

	settings = obs_output_get_settings(stream->output);

	drop_b = (int64_t)obs_data_get_int(settings, OPT_DROP_THRESHOLD);
	drop_p = (int64_t)obs_data_get_int(settings, OPT_PFRAME_DROP_THRESHOLD);
	stream->max_shutdown_time_sec =
		(int)obs_data_get_int(settings, OPT_MAX_SHUTDOWN_TIME_SEC);

	obs_encoder_t *venc = obs_output_get_video_encoder(stream->output);
	obs_encoder_t *aenc = obs_output_get_audio_encoder(stream->output, 0);
	obs_data_t *vsettings = obs_encoder_get_settings(venc);
	obs_data_t *asettings = obs_encoder_get_settings(aenc);

	circlebuf_free(&stream->dbr_frames);
	stream->audio_bitrate = (long)obs_data_get_int(asettings, "bitrate");
	stream->dbr_data_size = 0;
	stream->dbr_orig_bitrate = (long)obs_data_get_int(vsettings, "bitrate");
	stream->dbr_cur_bitrate = stream->dbr_orig_bitrate;
	stream->dbr_est_bitrate = 0;
	stream->dbr_inc_bitrate = stream->dbr_orig_bitrate / 10;
	stream->dbr_inc_timeout = 0;
	stream->dbr_enabled = obs_data_get_bool(settings, OPT_DYN_BITRATE);

	caps = obs_encoder_get_caps(venc);
	if ((caps & OBS_ENCODER_CAP_DYN_BITRATE) == 0)
		stream->dbr_enabled = false;

	if (obs_output_get_delay(stream->output) != 0)
		stream->dbr_enabled = false;

	if (stream->dbr_enabled)
		info("Dynamic bitrate enabled.  Dropped frames begone!");

	obs_data_release(vsettings);
	obs_data_release(asettings);

	if (drop_p < (drop_b + 200))
		drop_p = drop_b + 200;

	stream->drop_threshold_usec = 1000 * drop_b;
	stream->pframe_drop_threshold_usec = 1000 * drop_p;

	//bind_ip = obs_data_get_string(settings, OPT_BIND_IP);
	//dstr_copy(&stream->bind_ip, bind_ip);

	stream->low_latency_mode =
		obs_data_get_bool(settings, OPT_LOWLATENCY_ENABLED);

	obs_data_release(settings);
	return true;
}

static void *connect_thread(void *data)
{
	struct ramp_stream *stream = data;
	int ret;

	os_set_thread_name("ramp: connect_thread");

	if (!init_connect(stream)) {
		obs_output_signal_stop(stream->output, OBS_OUTPUT_ERROR);
		return NULL;
	}

	obs_service_t *service = obs_output_get_service(stream->output);
	if (!service) {
		obs_output_signal_stop(stream->output, OBS_OUTPUT_ERROR);
		return NULL;
	}

	const char *url = obs_service_get_url(service);
	const char *key = obs_service_get_key(service);
	const char *username = obs_service_get_username(service);
	const char *password = obs_service_get_password(service);

	if (!url || !*url) {
		warn("URL is empty");
		obs_output_signal_stop(stream->output, OBS_OUTPUT_BAD_PATH);
		return NULL;
	}

	info("Connecting to server URL %s...", url);

	stream->stream_int = ramp_start(url, key, username, password);
	if (!stream->stream_int) {
		obs_output_signal_stop(stream->output, -1);
		warn("Connection failed, can't init sdk");
		obs_output_signal_stop(stream->output, OBS_OUTPUT_ERROR);
	} else {
		ret = init_send(stream);
		if (ret != OBS_OUTPUT_SUCCESS) {
			obs_output_signal_stop(stream->output, ret);
			warn("Connection to %s failed: %d",
			     stream->stream_int->path, ret);
		}
	}

	os_atomic_set_bool(&stream->connecting, false);
	return NULL;
}

static bool ramp_stream_start(void *data)
{
	struct ramp_stream *stream = data;

	ramp_stop(&stream->stream_int);

	if (!obs_output_can_begin_data_capture(stream->output, 0))
		return false;

	if (!obs_output_initialize_encoders(stream->output, 0))
		return false;

	reset_semaphore(stream);
	os_atomic_set_bool(&stream->connecting, true);

	return pthread_create(&stream->connect_thread, NULL, connect_thread,
			      stream) == 0;
}

static inline bool add_packet(struct ramp_stream *stream,
			      struct encoder_packet *packet)
{
	circlebuf_push_back(&stream->packets, packet,
			    sizeof(struct encoder_packet));
	return true;
}

static inline size_t num_buffered_packets(struct ramp_stream *stream)
{
	return stream->packets.size / sizeof(struct encoder_packet);
}

static void drop_frames(struct ramp_stream *stream, const char *name,
			int highest_priority, bool pframes)
{
	UNUSED_PARAMETER(pframes);

	struct circlebuf new_buf = {0};
	int num_frames_dropped = 0;

#ifdef _DEBUG
	int start_packets = (int)num_buffered_packets(stream);
#else
	UNUSED_PARAMETER(name);
#endif

	circlebuf_reserve(&new_buf, sizeof(struct encoder_packet) * 8);

	while (stream->packets.size) {
		struct encoder_packet packet;
		circlebuf_pop_front(&stream->packets, &packet, sizeof(packet));

		/* do not drop audio data or video keyframes */
		if (packet.type == OBS_ENCODER_AUDIO ||
		    packet.drop_priority >= highest_priority) {
			circlebuf_push_back(&new_buf, &packet, sizeof(packet));

		} else {
			num_frames_dropped++;
			obs_encoder_packet_release(&packet);
		}
	}

	circlebuf_free(&stream->packets);
	stream->packets = new_buf;

	if (stream->min_priority < highest_priority)
		stream->min_priority = highest_priority;
	if (!num_frames_dropped)
		return;

	stream->dropped_frames += num_frames_dropped;

#ifdef _DEBUG
	debug("Dropped %s, prev packet count: %d, new packet count: %d", name,
	      start_packets, (int)num_buffered_packets(stream));
#endif
}

static bool find_first_video_packet(struct ramp_stream *stream,
				    struct encoder_packet *first)
{
	size_t count = stream->packets.size / sizeof(*first);

	for (size_t i = 0; i < count; i++) {
		struct encoder_packet *cur =
			circlebuf_data(&stream->packets, i * sizeof(*first));
		if (cur->type == OBS_ENCODER_VIDEO && !cur->keyframe) {
			*first = *cur;
			return true;
		}
	}

	return false;
}

static bool dbr_bitrate_lowered(struct ramp_stream *stream)
{
	long prev_bitrate = stream->dbr_prev_bitrate;
	long est_bitrate = 0;
	long new_bitrate;

	if (stream->dbr_est_bitrate &&
	    stream->dbr_est_bitrate < stream->dbr_cur_bitrate) {
		stream->dbr_data_size = 0;
		circlebuf_pop_front(&stream->dbr_frames, NULL,
				    stream->dbr_frames.size);
		est_bitrate = stream->dbr_est_bitrate / 100 * 100;
		if (est_bitrate < 50) {
			est_bitrate = 50;
		}
	}

	if (est_bitrate) {
		new_bitrate = est_bitrate;

	} else if (prev_bitrate) {
		new_bitrate = prev_bitrate;
		info("going back to prev bitrate");

	} else {
		return false;
	}

	if (new_bitrate == stream->dbr_cur_bitrate) {
		return false;
	}

	stream->dbr_prev_bitrate = 0;
	stream->dbr_cur_bitrate = new_bitrate;
	stream->dbr_inc_timeout = os_gettime_ns() + DBR_INC_TIMER;
	info("bitrate decreased to: %ld", stream->dbr_cur_bitrate);
	return true;
}

static void dbr_set_bitrate(struct ramp_stream *stream)
{
	obs_encoder_t *vencoder = obs_output_get_video_encoder(stream->output);
	obs_data_t *settings = obs_encoder_get_settings(vencoder);

	obs_data_set_int(settings, "bitrate", stream->dbr_cur_bitrate);
	obs_encoder_update(vencoder, settings);

	obs_data_release(settings);
}

static void dbr_inc_bitrate(struct ramp_stream *stream)
{
	stream->dbr_prev_bitrate = stream->dbr_cur_bitrate;
	stream->dbr_cur_bitrate += stream->dbr_inc_bitrate;

	if (stream->dbr_cur_bitrate >= stream->dbr_orig_bitrate) {
		stream->dbr_cur_bitrate = stream->dbr_orig_bitrate;
		info("bitrate increased to: %ld, done",
		     stream->dbr_cur_bitrate);
	} else if (stream->dbr_cur_bitrate < stream->dbr_orig_bitrate) {
		stream->dbr_inc_timeout = os_gettime_ns() + DBR_INC_TIMER;
		info("bitrate increased to: %ld, waiting",
		     stream->dbr_cur_bitrate);
	}
}

static void check_to_drop_frames(struct ramp_stream *stream, bool pframes)
{
	struct encoder_packet first;
	int64_t buffer_duration_usec;
	size_t num_packets = num_buffered_packets(stream);
	const char *name = pframes ? "p-frames" : "b-frames";
	int priority = pframes ? OBS_NAL_PRIORITY_HIGHEST
			       : OBS_NAL_PRIORITY_HIGH;
	int64_t drop_threshold = pframes ? stream->pframe_drop_threshold_usec
					 : stream->drop_threshold_usec;

	if (!pframes && stream->dbr_enabled) {
		if (stream->dbr_inc_timeout) {
			uint64_t t = os_gettime_ns();

			if (t >= stream->dbr_inc_timeout) {
				stream->dbr_inc_timeout = 0;
				dbr_inc_bitrate(stream);
				dbr_set_bitrate(stream);
			}
		}
	}

	if (num_packets < 5) {
		if (!pframes)
			stream->congestion = 0.0f;
		return;
	}

	if (!find_first_video_packet(stream, &first))
		return;

	buffer_duration_usec = stream->last_dts_usec - first.dts_usec;
	if (!pframes) {
		stream->congestion =
			(float)buffer_duration_usec / (float)drop_threshold;
	}

	if (stream->dbr_enabled) {
		bool bitrate_changed = false;

		if (pframes) {
			return;
		}

		if (buffer_duration_usec >= DBR_TRIGGER_USEC) {
			pthread_mutex_lock(&stream->dbr_mutex);
			bitrate_changed = dbr_bitrate_lowered(stream);
			pthread_mutex_unlock(&stream->dbr_mutex);
		}

		if (bitrate_changed) {
			//debug("buffer_duration_msec: %" PRId64,
			//      buffer_duration_usec / 1000);
			dbr_set_bitrate(stream);
		}
		return;
	}

	if (buffer_duration_usec > drop_threshold) {
		//debug("buffer_duration_usec: %" PRId64, buffer_duration_usec);
		drop_frames(stream, name, priority, pframes);
	}
}

static bool add_video_packet(struct ramp_stream *stream,
			     struct encoder_packet *packet)
{
	check_to_drop_frames(stream, false);
	check_to_drop_frames(stream, true);

	if (packet->drop_priority < stream->min_priority) {
		stream->dropped_frames++;
		return false;
	} else {
		stream->min_priority = 0;
	}

	stream->last_dts_usec = packet->dts_usec;
	return add_packet(stream, packet);
}

static void ramp_stream_data(void *data, struct encoder_packet *packet)
{
	struct ramp_stream *stream = data;
	struct encoder_packet new_packet;
	bool added_packet = false;

	if (disconnected(stream) || !active(stream))
		return;

	/* encoder fail */
	if (!packet) {
		os_atomic_set_bool(&stream->encode_error, true);
		os_sem_post(stream->send_sem);
		return;
	}

	if (packet->type == OBS_ENCODER_VIDEO) {
		if (!stream->got_first_video) {
			stream->start_dts_offset =
				get_ms_time(packet, packet->dts);
			stream->got_first_video = true;
		}

		obs_parse_avc_packet(&new_packet, packet);
	} else {
		obs_encoder_packet_ref(&new_packet, packet);
	}

	pthread_mutex_lock(&stream->packets_mutex);

	if (!disconnected(stream)) {
		added_packet = (packet->type == OBS_ENCODER_VIDEO)
				       ? add_video_packet(stream, &new_packet)
				       : add_packet(stream, &new_packet);
	}

	pthread_mutex_unlock(&stream->packets_mutex);

	if (added_packet)
		os_sem_post(stream->send_sem);
	else
		obs_encoder_packet_release(&new_packet);
}

static void ramp_stream_defaults(obs_data_t *defaults)
{
	obs_data_set_default_int(defaults, OPT_DROP_THRESHOLD, 700);
	obs_data_set_default_int(defaults, OPT_PFRAME_DROP_THRESHOLD, 900);
	obs_data_set_default_int(defaults, OPT_MAX_SHUTDOWN_TIME_SEC, 30);
	obs_data_set_default_string(defaults, OPT_BIND_IP, "default");
	obs_data_set_default_bool(defaults, OPT_NEWSOCKETLOOP_ENABLED, false);
	obs_data_set_default_bool(defaults, OPT_LOWLATENCY_ENABLED, false);
}

static obs_properties_t *ramp_stream_properties(void *unused)
{
	UNUSED_PARAMETER(unused);

	obs_properties_t *props = obs_properties_create();
	struct netif_saddr_data addrs = {0};
	obs_property_t *p;

	obs_properties_add_int(props, OPT_DROP_THRESHOLD,
			       obs_module_text("RTMPStream.DropThreshold"), 200,
			       10000, 100);

	p = obs_properties_add_list(props, OPT_BIND_IP,
				    obs_module_text("RTMPStream.BindIP"),
				    OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_STRING);

	obs_property_list_add_string(p, obs_module_text("Default"), "default");

	netif_get_addrs(&addrs);
	for (size_t i = 0; i < addrs.addrs.num; i++) {
		struct netif_saddr_item item = addrs.addrs.array[i];
		obs_property_list_add_string(p, item.name, item.addr);
	}
	netif_saddr_data_free(&addrs);

	obs_properties_add_bool(props, OPT_NEWSOCKETLOOP_ENABLED,
				obs_module_text("RTMPStream.NewSocketLoop"));
	obs_properties_add_bool(props, OPT_LOWLATENCY_ENABLED,
				obs_module_text("RTMPStream.LowLatencyMode"));

	return props;
}

static uint64_t ramp_stream_total_bytes_sent(void *data)
{
	struct ramp_stream *stream = data;
	return stream->total_bytes_sent;
}

static int ramp_stream_dropped_frames(void *data)
{
	struct ramp_stream *stream = data;
	return stream->dropped_frames;
}

static float ramp_stream_congestion(void *data)
{
	struct ramp_stream *stream = data;
	return stream->min_priority > 0 ? 1.0f : stream->congestion;
}

static int ramp_stream_connect_time(void *data)
{
	struct ramp_stream *stream = data;
	return stream->stream_int->rtmp->connect_time_ms;
}

struct obs_output_info ramp_output_info = {
	.id = "ramp_output",
	.flags = OBS_OUTPUT_AV | OBS_OUTPUT_ENCODED | OBS_OUTPUT_SERVICE,
	.encoded_video_codecs = "h264",
	.encoded_audio_codecs = "aac",
	.get_name = ramp_stream_getname,
	.create = ramp_stream_create,
	.destroy = ramp_stream_destroy,
	.start = ramp_stream_start,
	.stop = ramp_stream_stop,
	.encoded_packet = ramp_stream_data,
	.get_defaults = ramp_stream_defaults,
	.get_properties = ramp_stream_properties,
	.get_total_bytes = ramp_stream_total_bytes_sent,
	.get_congestion = ramp_stream_congestion,
	.get_connect_time_ms = ramp_stream_connect_time,
	.get_dropped_frames = ramp_stream_dropped_frames,
};
