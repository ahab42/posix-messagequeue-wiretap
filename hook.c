/* hook.c - LD_PRELOAD wiretap for POSIX mqueue calls.
 *
 * Hooks: mq_open, mq_send, mq_receive, mq_timedsend, mq_timedreceive.
 * Build:
 *   zig cc -target arm-linux-gnueabihf.2.31 -shared -fPIC -O2 -Wall -Wextra \
 *        -fno-builtin -fno-stack-protector -pthread hook.c -o libhook.so
 *
 *  TL;DR:
 *  we shove incoming events into a hopefully large queue and a second thread
 *  reads events from said queue and streams it to a TCP address.
 *
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "mqwt_proto.h"

#ifndef MQWT_SLOT_PAYLOAD
#define MQWT_SLOT_PAYLOAD (0x40000u) /* per-slot payload bytes (256K) */
#endif
#ifndef MQWT_QUEUE_SLOTS
#define MQWT_QUEUE_SLOTS 64
#endif
#ifndef MQWT_MAP_SLOTS
#define MQWT_MAP_SLOTS 64
#endif
#ifndef MQWT_POISON_SLOTS
#define MQWT_POISON_SLOTS 128
#endif

#define MQWT_CONNECT_TIMEOUT_MS 2000
#define MQWT_SOCK_TIMEOUT_SEC 2
#define MQWT_BACKOFF_START_MS 250
#define MQWT_BACKOFF_MAX_MS 1000

/* ------------------------------------------------------------------ */
/* static state                                                       */
/* ------------------------------------------------------------------ */

struct mqwt_slot {
	mqwt_frame_t f;
	unsigned char payload[MQWT_SLOT_PAYLOAD];
};

static struct mqwt_slot *g_queue; /* mmap'd ring */
static uint32_t g_slots;		  /* actual slot count after mmap */
static uint64_t g_head, g_tail;	  /* free-running FIFO indices */
static int g_fd = -1;			  /* owned by sender thread only */
static volatile int g_stop;

static uint32_t g_seq; /* per-call PRE/POST sequence id */

static pthread_mutex_t g_qmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_qcond = PTHREAD_COND_INITIALIZER;
static pthread_t g_sender_tid;
static int g_sender_started;
static uint64_t g_dropped;

/* seqs whose PRE frame was dropped: matching POST is dropped too */
static uint32_t g_poison[MQWT_POISON_SLOTS];
static unsigned g_poison_n;

/* mqd_t -> name map (BSS) */
struct mqwt_slot_map {
	int64_t key;
	int used;
	char name[MQWT_NAME_MAX];
};
static struct mqwt_slot_map g_map[MQWT_MAP_SLOTS];
static unsigned g_map_victim;

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

static void
mqwt_log(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(buf) - 1)
		n = (int)(sizeof(buf) - 2);
	buf[n++] = '\n';
	buf[n] = '\0';
	write(2, buf, (size_t)n);
}

static void
mqwt_msleep(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

/* read own memory without risk of SIGSEGV on a bad pointer (small structs) */
static int
mqwt_safe_read(const void *addr, size_t len, void *out)
{
	struct iovec local, remote;
	long r;

	if (!addr || !len || !out)
		return 0;
	local.iov_base = out;
	local.iov_len = len;
	remote.iov_base = (void *)(uintptr_t)addr;
	remote.iov_len = len;
	r = syscall(
		SYS_process_vm_readv, (long)getpid(), &local, 1UL, &remote, 1UL, 0UL);
	return r == (long)len;
}

static void
mqwt_copy_str(char *dst, size_t cap, const char *src)
{
	if (!src || !*src)
		src = "";
	strncpy(dst, src, cap - 1);
	dst[cap - 1] = '\0';
}

static char g_exename_buf[MQWT_NAME_MAX];

/* process executable name: /proc/self/exe, fallback argv[0], fallback
 * "[unknown]" */
static const char *
mqwt_exename(void)
{
	ssize_t n;

	if (g_exename_buf[0])
		return g_exename_buf;

	n = readlink("/proc/self/exe", g_exename_buf, sizeof(g_exename_buf) - 1);
	if (n > 0) {
		g_exename_buf[n] = '\0';
		return g_exename_buf;
	}

	{
		int dfd = open("/proc/self/cmdline", O_RDONLY);
		if (dfd >= 0) {
			n = read(dfd, g_exename_buf, sizeof(g_exename_buf) - 1);
			close(dfd);
			if (n > 0) {
				if ((size_t)n >= sizeof(g_exename_buf))
					n = sizeof(g_exename_buf) - 1;
				g_exename_buf[n] = '\0';
				/* argv[0] is the first NUL-terminated string */
				return g_exename_buf;
			}
		}
	}

	mqwt_copy_str(g_exename_buf, sizeof(g_exename_buf), "[unknown]");
	return g_exename_buf;
}

/* ------------------------------------------------------------------ */
/* mqd_t -> name map                                                  */
/* ------------------------------------------------------------------ */

static uint32_t
mqwt_hash(int64_t key)
{
	uint32_t h = (uint32_t)((uint64_t)key ^ ((uint64_t)key >> 32));
	h *= 2654435761u;
	h ^= h >> 16;
	return h;
}

static const char *
mqwt_map_get(int64_t key)
{
	uint32_t mask = MQWT_MAP_SLOTS - 1;
	uint32_t i = mqwt_hash(key) & mask;
	unsigned n;

	for (n = 0; n < MQWT_MAP_SLOTS; n++) {
		if (!g_map[i].used)
			return NULL;
		if (g_map[i].key == key)
			return g_map[i].name;
		i = (i + 1) & mask;
	}
	return NULL;
}

static void
mqwt_map_put(int64_t key, const char *name)
{
	uint32_t mask = MQWT_MAP_SLOTS - 1;
	uint32_t i = mqwt_hash(key) & mask;
	unsigned n;

	if (!name || !*name)
		return;

	for (n = 0; n < MQWT_MAP_SLOTS; n++) {
		if (g_map[i].used && g_map[i].key == key)
			break; /* overwrite */
		if (!g_map[i].used) {
			g_map[i].key = key;
			break;
		}
		i = (i + 1) & mask;
		if (i > mask)
			i = 0;
	}

	if (n == MQWT_MAP_SLOTS) {
		/* full: evict round-robin */
		i = g_map_victim % MQWT_MAP_SLOTS;
		g_map_victim++;
		g_map[i].key = key;
	}
	g_map[i].used = 1;
	mqwt_copy_str(g_map[i].name, sizeof(g_map[i].name), name);
}

/* ------------------------------------------------------------------ */
/* poison ring: drop the POST of a call whose PRE was dropped          */
/* ------------------------------------------------------------------ */

static int
mqwt_poison_has(uint32_t seq)
{
	unsigned i;

	for (i = 0; i < g_poison_n; i++)
		if (g_poison[i] == seq)
			return 1;
	return 0;
}

static void
mqwt_poison_add(uint32_t seq)
{
	if (g_poison_n < MQWT_POISON_SLOTS)
		g_poison[g_poison_n++] = seq;
	else
		g_poison[g_map_victim++ % MQWT_POISON_SLOTS] = seq;
}

static void
mqwt_poison_del(uint32_t seq)
{
	unsigned i, j;

	for (i = 0; i < g_poison_n; i++) {
		if (g_poison[i] == seq) {
			for (j = i; j + 1 < g_poison_n; j++)
				g_poison[j] = g_poison[j + 1];
			g_poison_n--;
			return;
		}
	}
}

/* ------------------------------------------------------------------ */
/* TCP endpoint: env -> conf file -> compiled default                  */
/* ------------------------------------------------------------------ */

#define MQWT_CONF_PATH "/tmp/libhook.conf.so"

/* split "ipv4:port" into host + numeric port; returns 0 on success */
static int
mqwt_split_addr(const char *addr, char *host, size_t hostlen, int *port)
{
	const char *colon;
	size_t hl;
	char *end;
	long p;

	colon = strrchr(addr, ':');
	if (!colon || colon == addr) {
		mqwt_log("[mqwt] addr '%s' malformed (want ipv4:port)", addr);
		return -1;
	}
	hl = (size_t)(colon - addr);
	if (hl >= hostlen) {
		mqwt_log("[mqwt] addr host too long");
		return -1;
	}
	memcpy(host, addr, hl);
	host[hl] = '\0';
	p = strtol(colon + 1, &end, 10);
	if (*end != '\0' || p <= 0 || p > 65535) {
		mqwt_log("[mqwt] addr bad port");
		return -1;
	}
	*port = (int)p;
	return 0;
}

/* config file fallback: text file containing only "ipaddress:port" */
static int
mqwt_read_conf(char *host, size_t hostlen, int *port)
{
	static char confbuf[64]; /* static, no dynamic allocation */
	int dfd;
	ssize_t n;

	dfd = open(MQWT_CONF_PATH, O_RDONLY);
	if (dfd < 0)
		return -1;
	n = read(dfd, confbuf, sizeof(confbuf) - 1);
	close(dfd);
	if (n <= 0)
		return -1;
	confbuf[n] = '\0';

	/* trim trailing whitespace/newlines */
	while (n > 0 && (confbuf[n - 1] == '\n' || confbuf[n - 1] == '\r' ||
						confbuf[n - 1] == ' ' || confbuf[n - 1] == '\t'))
		confbuf[--n] = '\0';
	if (!confbuf[0])
		return -1;

	return mqwt_split_addr(confbuf, host, hostlen, port);
}

static int
mqwt_parse_addr(char *host, size_t hostlen, int *port)
{
	const char *env = getenv("MQWT_ADDR");
	const char *def_host = "192.168.1.12";
	int def_port = 42424;

	/* 1. env */
	if (env && *env) {
		if (mqwt_split_addr(env, host, hostlen, port) == 0)
			return 0;
		return -1;
	}

	/* 2. config file */
	if (mqwt_read_conf(host, hostlen, port) == 0)
		return 0;

	/* 3. compiled-in default */
	mqwt_copy_str(host, hostlen, def_host);
	*port = def_port;
	return 0;
}

/* sender thread only; no locking needed */
static int
mqwt_connect(void)
{
	char host[64];
	int port = 0;
	struct sockaddr_in sa;
	struct timeval tv;
	int fd, fl, rc, one = 1;

	if (mqwt_parse_addr(host, sizeof(host), &port) != 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
		mqwt_log("[mqwt] '%s' not a numeric IPv4 address", host);
		return -1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		mqwt_log("[mqwt] socket: %s", strerror(errno));
		return -1;
	}

	/* nonblocking connect so a dead collector can't wedge the app */
	fl = fcntl(fd, F_GETFL, 0);
	if (fl >= 0)
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
	rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc != 0) {
		struct pollfd pfd;
		int serr = 0;
		socklen_t slen = sizeof(serr);

		if (errno != EINPROGRESS) {
			mqwt_log("[mqwt] connect %s:%d: %s", host, port, strerror(errno));
			close(fd);
			return -1;
		}
		pfd.fd = fd;
		pfd.events = POLLOUT;
		if (poll(&pfd, 1, MQWT_CONNECT_TIMEOUT_MS) != 1) {
			mqwt_log("[mqwt] connect %s:%d timeout", host, port);
			close(fd);
			return -1;
		}
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &serr, &slen);
		if (serr) {
			mqwt_log("[mqwt] connect %s:%d: %s", host, port, strerror(serr));
			close(fd);
			return -1;
		}
	}
	if (fl >= 0)
		fcntl(fd, F_SETFL, fl);

	tv.tv_sec = MQWT_SOCK_TIMEOUT_SEC;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return fd;
}

static int
mqwt_send_all(int fd, const unsigned char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* sender thread: owns the connection, drains the queue, reconnects    */
/* forever with backoff. A slot is consumed only once fully sent.      */
/* ------------------------------------------------------------------ */

static void *
mqwt_sender(void *arg)
{
	int backoff = MQWT_BACKOFF_START_MS;
	(void)arg;

	for (;;) {
		struct mqwt_slot *slot = NULL;
		int stop;

		pthread_mutex_lock(&g_qmutex);
		while (g_head == g_tail && !g_stop)
			pthread_cond_wait(&g_qcond, &g_qmutex);
		if (g_head != g_tail) {
			slot = &g_queue[g_head % g_slots];
			g_head++; /* slot reserved until fully sent */
		}
		stop = g_stop;
		pthread_mutex_unlock(&g_qmutex);

		if (!slot) {
			/* queue empty and g_stop: clean exit */
			break;
		}

		/* transmit, reconnecting forever until it lands */
		for (;;) {
			if (g_fd < 0) {
				g_fd = mqwt_connect();
				if (g_fd < 0) {
					mqwt_log("[mqwt] reconnect failed, "
							 "retrying in %dms",
						backoff);
					mqwt_msleep(backoff);
					if (backoff < MQWT_BACKOFF_MAX_MS)
						backoff *= 2;
					continue;
				}
				backoff = MQWT_BACKOFF_START_MS;
			}

			if (mqwt_send_all(g_fd, (const unsigned char *)slot,
					sizeof(mqwt_frame_t) + (size_t)slot->f.payload_len) == 0)
				break;

			/* send failed: reset and try again */
			mqwt_log("[mqwt] send failed: %s; reconnecting", strerror(errno));
			close(g_fd);
			g_fd = -1;
		}
		(void)stop;
	}

	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}
	return NULL;
}

static void
mqwt_start_sender(void)
{
	pthread_attr_t attr;

	if (g_sender_started || !g_queue)
		return;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&g_sender_tid, &attr, mqwt_sender, NULL) == 0)
		g_sender_started = 1;
	else
		mqwt_log("[mqwt] pthread_create failed: %s", strerror(errno));
	pthread_attr_destroy(&attr);
}

/* ------------------------------------------------------------------ */
/* queue: one anonymous mmap, slot count halves until it succeeds      */
/* ------------------------------------------------------------------ */

static void
mqwt_queue_init(void)
{
	size_t bytes;
	uint32_t n = MQWT_QUEUE_SLOTS;

	while (n >= 1) {
		bytes = (size_t)n * sizeof(struct mqwt_slot);
		g_queue = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (g_queue != MAP_FAILED) {
			g_slots = n;
			return;
		}
		mqwt_log("[mqwt] mmap of %zu bytes failed, halving slots", bytes);
		n /= 2;
	}
	g_queue = NULL;
	mqwt_log("[mqwt] mmap failed entirely, telemetry DISABLED");
}

/* ------------------------------------------------------------------ */
/* frame building + enqueue (app thread)                               */
/* ------------------------------------------------------------------ */

struct mqwt_evt {
	int func, phase;
	uint32_t seq;
	int64_t mqd;
	const char *name; /* mq_open */
	int oflag;
	uint32_t mode;
	const struct mq_attr *attr; /* mq_open */
	uint32_t prio;
	int prio_valid;
	size_t msg_len;
	const void *msg_ptr;	   /* payload to attach */
	const struct timespec *ts; /* timed variants */
	int64_t ret;
	int err;
};

static void
mqwt_enqueue(const struct mqwt_evt *e)
{
	mqwt_frame_t f;
	struct mqwt_slot *slot;
	size_t plen;
	int do_signal = 0;

	memset(&f, 0, sizeof(f));
	f.magic = MQWT_MAGIC;
	f.version = MQWT_VERSION;
	f.header_len = (uint16_t)sizeof(f);
	f.total_len = sizeof(f);
	f.seq = e->seq;
	f.pid = (uint32_t)getpid();
	f.tid = (uint32_t)syscall(SYS_gettid);
	f.func = (uint16_t)e->func;
	f.phase = (uint16_t)e->phase;
	f.mqd = e->mqd;

	if (e->func == MQWT_FN_MQ_OPEN) {
		mqwt_copy_str(f.mqd_name, sizeof(f.mqd_name), e->name);
		f.oflag = e->oflag;
		f.mode = e->mode;
		if (e->attr) {
			struct mq_attr a;
			if (mqwt_safe_read(e->attr, sizeof(a), &a)) {
				f.has_attr = 1;
				f.attr_flags = (int64_t)a.mq_flags;
				f.attr_maxmsg = (int64_t)a.mq_maxmsg;
				f.attr_msgsize = (int64_t)a.mq_msgsize;
				f.attr_curmsgs = (int64_t)a.mq_curmsgs;
			}
		}
	} else {
		mqwt_copy_str(f.mqd_name, sizeof(f.mqd_name), mqwt_map_get(e->mqd));
		if (!f.mqd_name[0])
			mqwt_copy_str(f.mqd_name, sizeof(f.mqd_name), MQWT_UNKNOWN);
	}

	/* name field carries the process executable name on every frame */
	mqwt_copy_str(f.name, sizeof(f.name), mqwt_exename());

	if (e->prio_valid) {
		f.msg_prio = e->prio;
		f.msg_prio_valid = 1;
	}
	f.msg_len = (uint64_t)e->msg_len;

	if (e->ts) {
		struct timespec t;
		if (mqwt_safe_read(e->ts, sizeof(t), &t)) {
			f.has_ts = 1;
			f.ts_sec = (int64_t)t.tv_sec;
			f.ts_nsec = (int64_t)t.tv_nsec;
		}
	}

	f.ret = e->ret;
	f.err = e->err;

	plen = (e->msg_ptr && e->msg_len) ? e->msg_len : 0;
	if (plen > MQWT_SLOT_PAYLOAD) {
		f.payload_trunc = 1;
		plen = MQWT_SLOT_PAYLOAD;
	}

	/* fire up the sender thread on first use (also covers fork-children) */
	pthread_mutex_lock(&g_qmutex);
	if (!g_sender_started && g_queue) {
		mqwt_start_sender();
	}

	if (!g_queue || g_tail - g_head >= g_slots) {
		/* queue full: drop this frame; poison PRE so the matching
		 * POST is dropped too, keeping the listener's pairing clean */
		if (e->phase == MQWT_PHASE_PRE)
			mqwt_poison_add(e->seq);
		else if (e->phase == MQWT_PHASE_POST && mqwt_poison_has(e->seq))
			mqwt_poison_del(e->seq);
		g_dropped++;
		if (g_dropped == 1 || (g_dropped % 32) == 0)
			mqwt_log("[mqwt] queue full, dropped frames so far: %llu",
				(unsigned long long)g_dropped);
	} else {
		slot = &g_queue[g_tail % g_slots];
		if (plen > 0)
			memcpy(slot->payload, e->msg_ptr, plen); /* plain copy */
		f.payload_len = (uint64_t)plen;
		f.total_len = (uint64_t)(sizeof(f) + plen);
		slot->f = f;
		g_tail++;
		do_signal = 1;
	}
	pthread_mutex_unlock(&g_qmutex);

	if (do_signal)
		pthread_cond_signal(&g_qcond);
}

/* ------------------------------------------------------------------ */
/* hooked functions                                                   */
/* ------------------------------------------------------------------ */

typedef mqd_t (*mq_open_fn)(const char *, int, ...);
typedef int (*mq_send_fn)(mqd_t, const char *, size_t, unsigned);
typedef ssize_t (*mq_receive_fn)(mqd_t, char *, size_t, unsigned *);
typedef int (*mq_timedsend_fn)(
	mqd_t, const char *, size_t, unsigned, const struct timespec *);
typedef ssize_t (*mq_timedreceive_fn)(
	mqd_t, char *, size_t, unsigned *, const struct timespec *);

static void *
mqwt_real(const char *name)
{
	void *p = dlsym(RTLD_NEXT, name);
	if (!p)
		mqwt_log("[mqwt] dlsym(%s) failed: %s", name, dlerror());
	return p;
}

mqd_t
mq_open(const char *name, int oflag, ...)
{
	static mq_open_fn real;
	mqd_t ret;
	mode_t mode = 0;
	struct mq_attr *attr = NULL;
	struct mqwt_evt e;
	int saved;
	uint32_t seq = __sync_add_and_fetch(&g_seq, 1u);

	if (!real && !(real = (mq_open_fn)mqwt_real("mq_open"))) {
		errno = ENOSYS;
		return (mqd_t)-1;
	}

	if (oflag & O_CREAT) {
		va_list ap;
		va_start(ap, oflag);
		mode = va_arg(ap, mode_t);
		attr = va_arg(ap, struct mq_attr *);
		va_end(ap);
	}

	memset(&e, 0, sizeof(e));
	e.func = MQWT_FN_MQ_OPEN;
	e.phase = MQWT_PHASE_PRE;
	e.seq = seq;
	e.mqd = -1;
	e.name = name;
	e.oflag = oflag;
	e.mode = (uint32_t)mode;
	e.attr = attr;
	mqwt_enqueue(&e);

	saved = errno;
	ret = real(name, oflag, mode, attr);
	saved = errno;

	e.phase = MQWT_PHASE_POST;
	e.mqd = (int64_t)(intptr_t)ret;
	e.ret = (int64_t)(intptr_t)ret;
	e.err = (ret >= 0) ? 0 : saved;
	mqwt_enqueue(&e);

	if (ret >= 0) {
		pthread_mutex_lock(&g_qmutex);
		mqwt_map_put((int64_t)(intptr_t)ret, name);
		pthread_mutex_unlock(&g_qmutex);
	}

	errno = saved;
	return ret;
}

int
mq_send(mqd_t mqd, const char *msg, size_t len, unsigned prio)
{
	static mq_send_fn real;
	int ret;
	struct mqwt_evt e;
	int saved;
	uint32_t seq = __sync_add_and_fetch(&g_seq, 1u);

	if (!real && !(real = (mq_send_fn)mqwt_real("mq_send"))) {
		errno = ENOSYS;
		return -1;
	}

	memset(&e, 0, sizeof(e));
	e.func = MQWT_FN_MQ_SEND;
	e.phase = MQWT_PHASE_PRE;
	e.seq = seq;
	e.mqd = (int64_t)(intptr_t)mqd;
	e.msg_ptr = msg;
	e.msg_len = len;
	e.prio = prio;
	e.prio_valid = 1;
	mqwt_enqueue(&e);

	saved = errno;
	ret = real(mqd, msg, len, prio);
	saved = errno;

	e.phase = MQWT_PHASE_POST;
	e.msg_ptr = NULL;
	e.msg_len = 0;
	e.ret = ret;
	e.err = (ret == 0) ? 0 : saved;
	mqwt_enqueue(&e);

	errno = saved;
	return ret;
}

ssize_t
mq_receive(mqd_t mqd, char *buf, size_t len, unsigned *prio)
{
	static mq_receive_fn real;
	ssize_t ret;
	struct mqwt_evt e;
	int saved;
	uint32_t seq = __sync_add_and_fetch(&g_seq, 1u);

	if (!real && !(real = (mq_receive_fn)mqwt_real("mq_receive"))) {
		errno = ENOSYS;
		return -1;
	}

	memset(&e, 0, sizeof(e));
	e.func = MQWT_FN_MQ_RECEIVE;
	e.phase = MQWT_PHASE_PRE;
	e.seq = seq;
	e.mqd = (int64_t)(intptr_t)mqd;
	e.msg_len = len;
	mqwt_enqueue(&e);

	saved = errno;
	ret = real(mqd, buf, len, prio);
	saved = errno;

	e.phase = MQWT_PHASE_POST;
	e.msg_ptr = buf;
	e.msg_len = (ret >= 0) ? (size_t)ret : 0;
	if (ret >= 0 && prio) {
		unsigned p;
		if (mqwt_safe_read(prio, sizeof(p), &p)) {
			e.prio = p;
			e.prio_valid = 1;
		}
	}
	e.ret = ret;
	e.err = (ret >= 0) ? 0 : saved;
	mqwt_enqueue(&e);

	errno = saved;
	return ret;
}

int
mq_timedsend(mqd_t mqd, const char *msg, size_t len, unsigned prio,
	const struct timespec *abs_timeout)
{
	static mq_timedsend_fn real;
	int ret;
	struct mqwt_evt e;
	int saved;
	uint32_t seq = __sync_add_and_fetch(&g_seq, 1u);

	if (!real && !(real = (mq_timedsend_fn)mqwt_real("mq_timedsend"))) {
		errno = ENOSYS;
		return -1;
	}

	memset(&e, 0, sizeof(e));
	e.func = MQWT_FN_MQ_TIMEDSEND;
	e.phase = MQWT_PHASE_PRE;
	e.seq = seq;
	e.mqd = (int64_t)(intptr_t)mqd;
	e.msg_ptr = msg;
	e.msg_len = len;
	e.prio = prio;
	e.prio_valid = 1;
	e.ts = abs_timeout;
	mqwt_enqueue(&e);

	saved = errno;
	ret = real(mqd, msg, len, prio, abs_timeout);
	saved = errno;

	e.phase = MQWT_PHASE_POST;
	e.msg_ptr = NULL;
	e.msg_len = 0;
	e.ret = ret;
	e.err = (ret == 0) ? 0 : saved;
	mqwt_enqueue(&e);

	errno = saved;
	return ret;
}

ssize_t
mq_timedreceive(mqd_t mqd, char *buf, size_t len, unsigned *prio,
	const struct timespec *abs_timeout)
{
	static mq_timedreceive_fn real;
	ssize_t ret;
	struct mqwt_evt e;
	int saved;
	uint32_t seq = __sync_add_and_fetch(&g_seq, 1u);

	if (!real && !(real = (mq_timedreceive_fn)mqwt_real("mq_timedreceive"))) {
		errno = ENOSYS;
		return -1;
	}

	memset(&e, 0, sizeof(e));
	e.func = MQWT_FN_MQ_TIMEDRECEIVE;
	e.phase = MQWT_PHASE_PRE;
	e.seq = seq;
	e.mqd = (int64_t)(intptr_t)mqd;
	e.msg_len = len;
	e.ts = abs_timeout;
	mqwt_enqueue(&e);

	saved = errno;
	ret = real(mqd, buf, len, prio, abs_timeout);
	saved = errno;

	e.phase = MQWT_PHASE_POST;
	e.msg_ptr = buf;
	e.msg_len = (ret >= 0) ? (size_t)ret : 0;
	if (ret >= 0 && prio) {
		unsigned p;
		if (mqwt_safe_read(prio, sizeof(p), &p)) {
			e.prio = p;
			e.prio_valid = 1;
		}
	}
	e.ret = ret;
	e.err = (ret >= 0) ? 0 : saved;
	mqwt_enqueue(&e);

	errno = saved;
	return ret;
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                          */
/* ------------------------------------------------------------------ */

static void
mqwt_atfork_child(void)
{
	/* only the forking thread survives in the child; reinit queue state */
	pthread_mutex_init(&g_qmutex, NULL);
	pthread_cond_init(&g_qcond, NULL);
	g_head = g_tail = 0;
	g_poison_n = 0;
	g_sender_started = 0;
	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}
	/* sender thread is respawned lazily on first hooked call */
}

__attribute__((constructor)) static void
mqwt_init(void)
{
	if (&pthread_atfork)
		pthread_atfork(NULL, NULL, mqwt_atfork_child);

	mqwt_queue_init();
	mqwt_start_sender();
	/* constructor no longer connects: the sender thread does, off the
	 * app's critical path, retrying forever until the listener is up */
}

__attribute__((destructor)) static void
mqwt_fini(void)
{
	/* best-effort: let the sender drain what's queued, then exit */
	pthread_mutex_lock(&g_qmutex);
	g_stop = 1;
	pthread_cond_broadcast(&g_qcond);
	pthread_mutex_unlock(&g_qmutex);
}
