/* listener.c - amd64 receiver for mq_wiretap telemetry.
 *
 * TODO: use something like `poll()` or `kqueue` instead of
 * thread-per-connection
 *
 * TL;DR - dumps incoming events to a sqlite db, feel free to use your favorite
 * database client to query stuff.
 *
 * Concurrent: one thread per client connection.
 * Folding: idle polls (PRE+POST ending in ETIMEDOUT/EAGAIN) are collapsed
 *   into one "timeouts" row per burst instead of flooding the log.
 * Persistence: SQLite database <outdir>/mqwt.db (WAL mode, safe to read
 *   with python/sqlite3 while the listener runs):
 *
 *   calls(id, t, pid, tid, seq, exe, func, mqd, mq, oflag, mode,
 *         attr_flags, attr_max, attr_msgsize, attr_cur, ts_sec, ts_nsec,
 *         req_prio, req_len, ret, err, len, prio, pre_missing, payload)
 *   timeouts(id, t, count, errno, pid, tid, exe, func, mqd, mq)
 *
 * Build: make
 * Usage: ./listener [port] [outdir]      defaults: 42424 ./logs
 * Query: sqlite3 logs/mqwt.db 'select * from calls limit 5;'
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "mqwt_proto.h"

#define HASH_BUCKETS 4096
#define FOLD_IDLE_SEC 10
#define MAX_PAYLOAD 1048576

/* ------------------------------------------------------------------ */
/* wire helpers                                                        */
/* ------------------------------------------------------------------ */

static const char *
func_name(uint16_t f)
{
	switch (f) {
	case MQWT_FN_MQ_OPEN:
		return "mq_open";
	case MQWT_FN_MQ_SEND:
		return "mq_send";
	case MQWT_FN_MQ_RECEIVE:
		return "mq_receive";
	case MQWT_FN_MQ_TIMEDSEND:
		return "mq_timedsend";
	case MQWT_FN_MQ_TIMEDRECEIVE:
		return "mq_timedreceive";
	default:
		return "?";
	}
}

static int
read_exact(int fd, void *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = recv(fd, (char *)buf + off, len - off, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static void
hexdump(FILE *fp, const unsigned char *p, size_t n)
{
	size_t i, j;

	for (i = 0; i < n; i += 16) {
		fprintf(fp, "      %04zx ", i);
		for (j = 0; j < 16 && i + j < n; j++)
			fprintf(fp, "%02x ", p[i + j]);
		fprintf(fp, " |");
		for (j = 0; j < 16 && i + j < n; j++)
			fputc((p[i + j] >= 32 && p[i + j] < 127) ? p[i + j] : '.', fp);
		fprintf(fp, "|\n");
	}
}

/* ------------------------------------------------------------------ */
/* data structures                                                     */
/* ------------------------------------------------------------------ */

/* PRE frame waiting for its POST */
struct callrec {
	uint32_t pid;
	uint32_t seq;
	mqwt_frame_t f;
	struct callrec *next;
};

/* folded timeout burst */
struct foldrec {
	uint32_t pid, tid;
	uint16_t func, err;
	int64_t mqd;
	char exe[MQWT_NAME_MAX], mq[MQWT_NAME_MAX];
	unsigned long count;
	time_t first, last;
	struct foldrec *next;
};

/* ------------------------------------------------------------------ */
/* sqlite                                                              */
/* ------------------------------------------------------------------ */

static sqlite3 *g_db;
static char g_outdir[256] = "./logs";
static pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;

static sqlite3_stmt *g_ins_call;
static sqlite3_stmt *g_ins_timeout;

static const char SQL_SCHEMA[] =
	"PRAGMA journal_mode=WAL;"
	"PRAGMA synchronous=NORMAL;"
	"CREATE TABLE IF NOT EXISTS calls ("
	"  id INTEGER PRIMARY KEY,"
	"  t TEXT NOT NULL," /* UTC receipt time */
	"  epoch INTEGER NOT NULL,"
	"  pid INTEGER, tid INTEGER, seq INTEGER,"
	"  exe TEXT, func TEXT, mqd INTEGER, mq TEXT,"
	"  oflag INTEGER, mode INTEGER,"
	"  attr_flags INTEGER, attr_max INTEGER, attr_msgsize INTEGER,"
	"  attr_cur INTEGER,"
	"  ts_sec INTEGER, ts_nsec INTEGER," /* abs_timeout from timed* */
	"  req_prio INTEGER, req_len INTEGER,"
	"  ret INTEGER, err INTEGER, len INTEGER, prio INTEGER,"
	"  pre_missing INTEGER,"
	"  payload BLOB);"
	"CREATE INDEX IF NOT EXISTS idx_calls_mq ON calls(mq);"
	"CREATE INDEX IF NOT EXISTS idx_calls_func ON calls(func);"
	"CREATE TABLE IF NOT EXISTS timeouts ("
	"  id INTEGER PRIMARY KEY,"
	"  t TEXT NOT NULL, epoch INTEGER NOT NULL,"
	"  count INTEGER, errno INTEGER,"
	"  pid INTEGER, tid INTEGER, exe TEXT, func TEXT,"
	"  mqd INTEGER, mq TEXT);"
	"CREATE INDEX IF NOT EXISTS idx_timeouts_mq ON timeouts(mq);";

static const char SQL_INS_CALL[] =
	"INSERT INTO calls(t,epoch,pid,tid,seq,exe,func,mqd,mq,oflag,mode,"
	"attr_flags,attr_max,attr_msgsize,attr_cur,ts_sec,ts_nsec,"
	"req_prio,req_len,ret,err,len,prio,pre_missing,payload)"
	" VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,"
	"?17,?18,?19,?20,?21,?22,?23,?24,?25);";

static const char SQL_INS_TIMEOUT[] =
	"INSERT INTO timeouts(t,epoch,count,errno,pid,tid,exe,func,mqd,mq)"
	" VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10);";

static void
iso_time(char *buf, size_t n, time_t t)
{
	struct tm tm;

	gmtime_r(&t, &tm);
	strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static int
db_open(void)
{
	char path[512];
	int rc;

	snprintf(path, sizeof(path), "%s/mqwt.db", g_outdir);
	mkdir(g_outdir, 0777);
	rc = sqlite3_open(path, &g_db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "sqlite open %s: %s\n", path, sqlite3_errmsg(g_db));
		return -1;
	}
	rc = sqlite3_exec(g_db, SQL_SCHEMA, NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "sqlite schema: %s\n", sqlite3_errmsg(g_db));
		return -1;
	}
	sqlite3_prepare_v2(g_db, SQL_INS_CALL, -1, &g_ins_call, NULL);
	sqlite3_prepare_v2(g_db, SQL_INS_TIMEOUT, -1, &g_ins_timeout, NULL);
	return 0;
}

/* insert one completed call (PRE+POST merged); caller holds g_db_mutex */
static void
db_call(struct callrec *pre, mqwt_frame_t *post, const unsigned char *payload)
{
	sqlite3_stmt *st = g_ins_call;
	char tbuf[32];
	time_t now = time(NULL);

	if (!st)
		return;
	iso_time(tbuf, sizeof(tbuf), now);

	sqlite3_bind_text(st, 1, tbuf, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 2, (sqlite3_int64)now);
	sqlite3_bind_int(st, 3, post->pid);
	sqlite3_bind_int(st, 4, post->tid);
	sqlite3_bind_int64(st, 5, (sqlite3_int64)post->seq);
	sqlite3_bind_text(st, 6, post->name, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 7, func_name(post->func), -1, SQLITE_STATIC);
	sqlite3_bind_int64(st, 8, (sqlite3_int64)post->mqd);
	sqlite3_bind_text(st, 9, post->mqd_name, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int(st, 10, pre ? pre->f.oflag : 0);
	sqlite3_bind_int(st, 11, pre ? (int)pre->f.mode : 0);
	sqlite3_bind_int64(st, 12, pre ? pre->f.attr_flags : 0);
	sqlite3_bind_int64(st, 13, pre ? pre->f.attr_maxmsg : 0);
	sqlite3_bind_int64(st, 14, pre ? pre->f.attr_msgsize : 0);
	sqlite3_bind_int64(st, 15, pre ? pre->f.attr_curmsgs : 0);
	sqlite3_bind_int64(st, 16, pre ? pre->f.ts_sec : 0);
	sqlite3_bind_int64(st, 17, pre ? pre->f.ts_nsec : 0);
	sqlite3_bind_int(st, 18, pre ? (int)pre->f.msg_prio : 0);
	sqlite3_bind_int64(st, 19, pre ? (sqlite3_int64)pre->f.msg_len : 0);
	sqlite3_bind_int64(st, 20, (sqlite3_int64)post->ret);
	sqlite3_bind_int(st, 21, (int)post->err);
	sqlite3_bind_int64(st, 22, (sqlite3_int64)post->msg_len);
	sqlite3_bind_int(st, 23, (int)post->msg_prio);
	sqlite3_bind_int(st, 24, pre ? 0 : 1);
	if (post->payload_len > 0 && post->payload_len <= MAX_PAYLOAD)
		sqlite3_bind_blob(
			st, 25, payload, (int)post->payload_len, SQLITE_STATIC);
	else
		sqlite3_bind_null(st, 25);

	if (sqlite3_step(st) != SQLITE_DONE)
		fprintf(stderr, "sqlite insert call: %s\n", sqlite3_errmsg(g_db));
	sqlite3_reset(st);
	sqlite3_clear_bindings(st);
}

/* insert one folded timeout burst; caller holds g_db_mutex */
static void
db_timeout(struct foldrec *r)
{
	sqlite3_stmt *st = g_ins_timeout;
	char tbuf[32];
	time_t now = time(NULL);

	if (!st)
		return;
	iso_time(tbuf, sizeof(tbuf), now);

	sqlite3_bind_text(st, 1, tbuf, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 2, (sqlite3_int64)now);
	sqlite3_bind_int64(st, 3, (sqlite3_int64)r->count);
	sqlite3_bind_int(st, 4, (int)r->err);
	sqlite3_bind_int(st, 5, r->pid);
	sqlite3_bind_int(st, 6, r->tid);
	sqlite3_bind_text(st, 7, r->exe, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 8, func_name(r->func), -1, SQLITE_STATIC);
	sqlite3_bind_int64(st, 9, (sqlite3_int64)r->mqd);
	sqlite3_bind_text(st, 10, r->mq, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(st) != SQLITE_DONE)
		fprintf(stderr, "sqlite insert timeout: %s\n", sqlite3_errmsg(g_db));
	sqlite3_reset(st);
	sqlite3_clear_bindings(st);
}

/* ------------------------------------------------------------------ */
/* completed-call store (PRE frame waiting for its POST)               */
/* ------------------------------------------------------------------ */

static struct callrec *g_calls[HASH_BUCKETS];

static unsigned
call_hash(uint32_t pid, uint32_t seq)
{
	return (unsigned)((pid * 2654435761u) ^ (seq * 0x9e3779b9u)) &
		   (HASH_BUCKETS - 1);
}

static void
call_store(mqwt_frame_t *f)
{
	unsigned h = call_hash(f->pid, (uint32_t)f->seq);
	struct callrec *c = calloc(1, sizeof(*c));

	if (!c)
		return;
	c->pid = f->pid;
	c->seq = (uint32_t)f->seq;
	c->f = *f;
	c->next = g_calls[h];
	g_calls[h] = c;
}

static struct callrec *
call_take(uint32_t pid, uint32_t seq)
{
	unsigned h = call_hash(pid, seq);
	struct callrec **pp = &g_calls[h];

	for (; *pp; pp = &(*pp)->next) {
		if ((*pp)->pid == pid && (*pp)->seq == seq) {
			struct callrec *c = *pp;
			*pp = c->next;
			return c;
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* folded timeout bursts                                               */
/* ------------------------------------------------------------------ */

static struct foldrec *g_folds;

static int
is_idle_errno(uint16_t e)
{
	return e == ETIMEDOUT || e == EAGAIN;
}

static int
is_msg_func(uint16_t f)
{
	return f == MQWT_FN_MQ_SEND || f == MQWT_FN_MQ_TIMEDSEND ||
		   f == MQWT_FN_MQ_RECEIVE || f == MQWT_FN_MQ_TIMEDRECEIVE;
}

/* emit + free one fold record; caller holds g_db_mutex */
static void
fold_flush_locked(struct foldrec *r)
{
	fprintf(stderr, "[fold] %s %s mq=%s errno=%d: %lu timeouts\n", r->exe,
		func_name(r->func), r->mq, (int)r->err, r->count);
	db_timeout(r);
	free(r);
}

/* flush folds idle for FOLD_IDLE_SEC (streak ended).
 * pid!=0 flushes that pid only (connection closed) */
static void
fold_sweep(time_t now, uint32_t pid)
{
	struct foldrec **pp = &g_folds;

	while (*pp) {
		struct foldrec *r = *pp;

		if (pid ? r->pid == pid : (now - r->last >= FOLD_IDLE_SEC)) {
			*pp = r->next;
			fold_flush_locked(r);
		} else {
			pp = &r->next;
		}
	}
}

/* a non-timeout frame from the same thread ends any open timeout streak */
static void
fold_break(uint32_t pid, uint32_t tid)
{
	struct foldrec **pp = &g_folds;

	while (*pp) {
		struct foldrec *r = *pp;

		if (r->pid == pid && r->tid == tid) {
			*pp = r->next;
			fold_flush_locked(r);
		} else {
			pp = &r->next;
		}
	}
}

/* ------------------------------------------------------------------ */
/* periodic maintenance                                                */
/* ------------------------------------------------------------------ */

static void *
periodic(void *arg)
{
	(void)arg;
	for (;;) {
		time_t now = time(NULL);

		pthread_mutex_lock(&g_db_mutex);
		fold_sweep(now, 0);
		pthread_mutex_unlock(&g_db_mutex);
		sleep(FOLD_IDLE_SEC);
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* per-frame processing                                                */
/* ------------------------------------------------------------------ */

static void
handle(int fd)
{
	static unsigned char payload[MAX_PAYLOAD];
	uint32_t pid = 0;

	for (;;) {
		mqwt_frame_t f;
		uint64_t plen, i;
		struct callrec *pre;
		time_t now;

		if (read_exact(fd, &f, sizeof(f)) != 0)
			break;
		if (f.magic != MQWT_MAGIC || f.header_len != sizeof(f)) {
			fprintf(stderr,
				"listener: bad frame magic=%08x hl=%u, dropping connection\n",
				f.magic, f.header_len);
			break;
		}

		plen = f.payload_len;
		if (plen > MAX_PAYLOAD)
			plen = MAX_PAYLOAD;
		if (plen && read_exact(fd, payload, (size_t)plen) != 0)
			break;
		for (i = plen; i < f.payload_len; i++) {
			char c;

			if (read_exact(fd, &c, 1) != 0)
				goto done;
		}
		pid = f.pid;
		now = time(NULL);

		if (f.phase == MQWT_PHASE_PRE) {
			call_store(&f);
			continue;
		}

		/* ---- POST ---- */
		pre = call_take(f.pid, (uint32_t)f.seq);

		/* idle poll: fold the pair instead of recording it */
		if (f.ret < 0 && is_idle_errno((uint16_t)f.err) &&
			is_msg_func(f.func)) {
			struct foldrec **pp = &g_folds;
			struct foldrec *r;
			int found = 0;

			pthread_mutex_lock(&g_db_mutex);
			for (; *pp; pp = &(*pp)->next) {
				r = *pp;
				if (r->pid == f.pid && r->tid == f.tid && r->func == f.func &&
					r->mqd == f.mqd && r->err == f.err) {
					r->count++;
					r->last = now;
					found = 1;
					break;
				}
			}
			if (!found) {
				r = calloc(1, sizeof(*r));
				if (r) {
					r->pid = f.pid;
					r->tid = f.tid;
					r->func = f.func;
					r->err = f.err;
					r->mqd = f.mqd;
					snprintf(r->exe, sizeof(r->exe), "%s", f.name);
					snprintf(r->mq, sizeof(r->mq), "%s", f.mqd_name);
					r->count = 1;
					r->first = r->last = now;
					*pp = r;
				}
			}
			pthread_mutex_unlock(&g_db_mutex);
			free(pre);
			continue;
		}

		/* real call: ends any open timeout streak on this thread */
		pthread_mutex_lock(&g_db_mutex);
		fold_break(f.pid, f.tid);
		db_call(pre, &f, payload);
		pthread_mutex_unlock(&g_db_mutex);

		/* pretty print (merged) */
		printf("[%llu] %s pid=%u tid=%u seq=%llu\n", (unsigned long long)f.seq,
			func_name(f.func), f.pid, f.tid, (unsigned long long)f.seq);
		printf("  mqd=%lld mq='%s' exe='%s'\n", (long long)f.mqd, f.mqd_name,
			f.name);
		if (pre) {
			if (pre->f.func == MQWT_FN_MQ_OPEN)
				printf("  oflag=%#x mode=%#o attr(%d): "
					   "flags=%lld max=%lld msgsize=%lld cur=%lld\n",
					(unsigned)pre->f.oflag, (unsigned)pre->f.mode,
					pre->f.has_attr, (long long)pre->f.attr_flags,
					(long long)pre->f.attr_maxmsg,
					(long long)pre->f.attr_msgsize,
					(long long)pre->f.attr_curmsgs);
			if (pre->f.has_ts)
				printf("  ts=%lld.%09lld\n", (long long)pre->f.ts_sec,
					(long long)pre->f.ts_nsec);
			if (pre->f.msg_prio_valid)
				printf("  prio=%u\n", pre->f.msg_prio);
		}
		printf("  ret=%lld errno=%d (%s) len=%llu\n", (long long)f.ret,
			(int)f.err, f.err ? strerror((int)f.err) : "OK",
			(unsigned long long)f.msg_len);
		if (plen) {
			printf("  payload:\n");
			hexdump(stdout, payload, (size_t)plen);
		}
		printf("\n");
		fflush(stdout);

		free(pre);
	}
done:
	if (pid) {
		pthread_mutex_lock(&g_db_mutex);
		fold_sweep(time(NULL), pid);
		pthread_mutex_unlock(&g_db_mutex);
	}
}

/* ------------------------------------------------------------------ */
/* server                                                              */
/* ------------------------------------------------------------------ */

static void *
handle_thread(void *arg)
{
	int fd = (int)(intptr_t)arg;

	printf("== connection\n");
	handle(fd);
	close(fd);
	printf("== disconnected\n");
	return NULL;
}

int
main(int argc, char **argv)
{
	int port = argc > 1 ? atoi(argv[1]) : 42424;
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa;
	pthread_t pt;
	int one = 1;

	if (argc > 2)
		snprintf(g_outdir, sizeof(g_outdir), "%s", argv[2]);
	if (db_open() != 0)
		return 1;

	if (s < 0) {
		perror("socket");
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons((uint16_t)port);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(s, 16) < 0) {
		perror("bind/listen");
		return 1;
	}

	pthread_create(&pt, NULL, periodic, NULL);
	pthread_detach(pt);

	printf("listening on :%d, db=%s/mqwt.db\n", port, g_outdir);
	for (;;) {
		int c = accept(s, NULL, NULL);
		pthread_t t;

		if (c < 0)
			continue;
		if (pthread_create(&t, NULL, handle_thread, (void *)(intptr_t)c) == 0)
			pthread_detach(t);
		else
			close(c);
	}
}
