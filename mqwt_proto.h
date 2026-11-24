/* mqwt_proto.h - shared wire format for mq_wiretap hook + listener.
 *
 * assumed that listener and hook are compiled to same byte order.
 */
#ifndef MQWT_PROTO_H
#define MQWT_PROTO_H

#include <stdint.h>

#define MQWT_MAGIC 0x5457514Du /* "MQWT" read as LE u32 */
#define MQWT_VERSION 1u
#define MQWT_NAME_MAX 256
#define MQWT_UNKNOWN "<?\?unknown\?>"

/* func */
#define MQWT_FN_MQ_OPEN 1
#define MQWT_FN_MQ_SEND 2
#define MQWT_FN_MQ_RECEIVE 3
#define MQWT_FN_MQ_TIMEDSEND 4
#define MQWT_FN_MQ_TIMEDRECEIVE 5

/* phase */
#define MQWT_PHASE_PRE 0
#define MQWT_PHASE_POST 1

typedef struct __attribute__((packed)) {
	uint32_t magic;		 /* MQWT_MAGIC */
	uint16_t version;	 /* MQWT_VERSION */
	uint16_t header_len; /* sizeof(mqwt_frame_t) */
	uint64_t total_len;	 /* header_len + payload_len */
	uint64_t seq;		 /* same value for PRE and POST frame of one call */
	uint32_t pid;
	uint32_t tid;
	uint16_t func;	/* MQWT_FN_* */
	uint16_t phase; /* MQWT_PHASE_* */
	int64_t mqd;	/* raw mqd_t as int; -1 if N/A (mq_open PRE) */
	char mqd_name[MQWT_NAME_MAX]; /* mqd expanded to string */
	char name[MQWT_NAME_MAX];	  /* name arg (mq_open only) */
	int32_t oflag;				  /* mq_open */
	uint32_t mode;				  /* mq_open */
	int32_t has_attr;			  /* mq_open attr arg */
	uint32_t _pad0;
	int64_t attr_flags;
	int64_t attr_maxmsg;
	int64_t attr_msgsize;
	int64_t attr_curmsgs;
	uint32_t msg_prio; /* send: prio arg. receive: prio out val (POST) */
	uint32_t msg_prio_valid;
	uint64_t
		msg_len; /* send: len arg. receive: requested (PRE) / received (POST) */
	int32_t has_ts; /* timed variants */
	uint32_t _pad1;
	int64_t ts_sec;
	int64_t ts_nsec;
	int64_t ret; /* POST: return value. PRE: 0 */
	int32_t err; /* POST: errno. PRE: 0 */
	uint32_t _pad2;
	uint64_t payload_len;	/* bytes of payload following the header */
	uint32_t payload_trunc; /* payload was clamped to scratch buffer */
	uint32_t _pad3;
} mqwt_frame_t;

#endif /* MQWT_PROTO_H */
