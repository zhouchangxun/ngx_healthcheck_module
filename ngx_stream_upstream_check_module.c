/*
 * Copyright (C) 2017- Changxun Zhou(changxunzhou@qq.com)
 * desc: stream upstream server health check.
 */


#include <nginx.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_http.h>

#include "ngx_stream_upstream_check_module.h"
#include "common.h.in"


typedef struct {
    ngx_buf_t                                send;
    ngx_buf_t                                recv;

    ngx_uint_t                               state;
    ngx_http_status_t                        status;

    size_t                                   padding;
    size_t                                   length;
} ngx_stream_upstream_check_ctx_t;


#define NGX_HTTP_CHECK_CONNECT_DONE          0x0001
#define NGX_HTTP_CHECK_SEND_DONE             0x0002
#define NGX_HTTP_CHECK_RECV_DONE             0x0004
#define NGX_HTTP_CHECK_ALL_DONE              0x0008



#define NGX_CHECK_TYPE_TCP                   0x0001
#define NGX_CHECK_TYPE_HTTP                  0x0002
#define NGX_CHECK_TYPE_UDP                   0x0004


#define NGX_CHECK_HTTP_2XX                   0x0002
#define NGX_CHECK_HTTP_3XX                   0x0004
#define NGX_CHECK_HTTP_4XX                   0x0008
#define NGX_CHECK_HTTP_5XX                   0x0010
#define NGX_CHECK_HTTP_ERR                   0x8000

typedef void (*ngx_stream_upstream_check_status_format_pt) (ngx_buf_t *b,
                                                            ngx_upstream_check_peers_t *peers, ngx_uint_t flag);

typedef struct {
    ngx_str_t                                format;
    ngx_str_t                                content_type;

    ngx_stream_upstream_check_status_format_pt output;
} ngx_check_status_conf_t;


#define NGX_CHECK_STATUS_DOWN                0x0001
#define NGX_CHECK_STATUS_UP                  0x0002

typedef struct {
    ngx_check_status_conf_t                 *format;
    ngx_flag_t                               flag;
} ngx_stream_upstream_check_status_ctx_t;


typedef ngx_int_t (*ngx_stream_upstream_check_status_command_pt)
        (ngx_stream_upstream_check_status_ctx_t *ctx, ngx_str_t *value);

typedef struct {
    ngx_str_t                                 name;
    ngx_stream_upstream_check_status_command_pt handler;
} ngx_check_status_command_t;

//zhocux stream check module main config data.
typedef struct {
    ngx_uint_t                               check_shm_size;
    ngx_upstream_check_peers_t         *peers;
} ngx_stream_upstream_check_main_conf_t;




typedef struct {
    ngx_check_status_conf_t                 *format;
} ngx_stream_upstream_check_loc_conf_t;


static ngx_int_t ngx_stream_upstream_check_add_timers(ngx_cycle_t *cycle);

static ngx_int_t ngx_stream_upstream_check_peek_one_byte(ngx_connection_t *c);

static void ngx_stream_upstream_check_begin_handler(ngx_event_t *event);
static void ngx_stream_upstream_check_connect_handler(ngx_event_t *event);

static void ngx_stream_upstream_check_peek_handler(ngx_event_t *event);

static void ngx_stream_upstream_check_send_handler(ngx_event_t *event);
static void ngx_stream_upstream_check_recv_handler(ngx_event_t *event);

static void ngx_stream_upstream_check_discard_handler(ngx_event_t *event);
static void ngx_stream_upstream_check_dummy_handler(ngx_event_t *event);

static ngx_int_t ngx_stream_upstream_check_http_init(
        ngx_upstream_check_peer_t *peer);
static ngx_int_t ngx_stream_upstream_check_http_parse(
        ngx_upstream_check_peer_t *peer);
static ngx_int_t ngx_stream_upstream_check_parse_status_line(
        ngx_stream_upstream_check_ctx_t *ctx, ngx_buf_t *b,
        ngx_http_status_t *status);
static void ngx_stream_upstream_check_http_reinit(
        ngx_upstream_check_peer_t *peer);


static void ngx_stream_upstream_check_status_update(
        ngx_upstream_check_peer_t *peer,
        ngx_int_t result);

static void ngx_stream_upstream_check_clean_event(
        ngx_upstream_check_peer_t *peer);

static void ngx_stream_upstream_check_timeout_handler(ngx_event_t *event);
static void ngx_stream_upstream_check_finish_handler(ngx_event_t *event);

static ngx_int_t ngx_stream_upstream_check_need_exit();
static void ngx_stream_upstream_check_clear_all_events();


static ngx_int_t ngx_stream_upstream_check_addr_change_port(ngx_pool_t *pool,
                                                            ngx_addr_t *dst, ngx_addr_t *src, ngx_uint_t port);

static ngx_check_conf_t *ngx_http_get_check_type_conf(ngx_str_t *str);

static char *ngx_stream_upstream_check(ngx_conf_t *cf,
                                       ngx_command_t *cmd, void *conf);
static char *ngx_stream_upstream_check_keepalive_requests(ngx_conf_t *cf,
                                                          ngx_command_t *cmd, void *conf);
static char *ngx_stream_upstream_check_http_send(ngx_conf_t *cf,
                                                 ngx_command_t *cmd, void *conf);
static char *ngx_stream_upstream_check_http_expect_alive(ngx_conf_t *cf,
                                                         ngx_command_t *cmd, void *conf);


static char *ngx_stream_upstream_check_shm_size(ngx_conf_t *cf,
                                                ngx_command_t *cmd, void *conf);

static void *ngx_stream_upstream_check_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_check_init_main_conf(ngx_conf_t *cf,
                                                      void *conf);

static void *ngx_stream_upstream_check_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_check_init_srv_conf(ngx_conf_t *cf, void *conf);
#define SHM_NAME_LEN 256

static char *ngx_stream_upstream_check_init_shm(ngx_conf_t *cf, void *conf);

static ngx_int_t ngx_stream_upstream_check_get_shm_name(ngx_str_t *shm_name,
                                                        ngx_pool_t *pool, ngx_uint_t generation);
static ngx_shm_zone_t *ngx_shared_memory_find(ngx_cycle_t *cycle,
                                              ngx_str_t *name, void *tag);
static ngx_upstream_check_peer_shm_t *
ngx_stream_upstream_check_find_shm_peer(ngx_upstream_check_peers_shm_t *peers_shm,
                                        ngx_addr_t *addr, ngx_str_t *upstream_name);

static ngx_int_t ngx_stream_upstream_check_init_shm_peer(
        ngx_upstream_check_peer_shm_t *peer_shm,
        ngx_upstream_check_peer_shm_t *opeer_shm,
        ngx_uint_t init_down, ngx_pool_t *pool, ngx_str_t *peer_name, ngx_str_t *upstream_name);

static ngx_int_t ngx_stream_upstream_check_init_shm_zone(
        ngx_shm_zone_t *shm_zone, void *data);


static ngx_int_t ngx_stream_upstream_check_init_process(ngx_cycle_t *cycle);


static ngx_conf_bitmask_t  ngx_check_http_expect_alive_masks[] = {
        { ngx_string("http_2xx"), NGX_CHECK_HTTP_2XX },
        { ngx_string("http_3xx"), NGX_CHECK_HTTP_3XX },
        { ngx_string("http_4xx"), NGX_CHECK_HTTP_4XX },
        { ngx_string("http_5xx"), NGX_CHECK_HTTP_5XX },
        { ngx_null_string, 0 }
};


static ngx_command_t  ngx_stream_upstream_check_commands[] = {

        { ngx_string("check"),
          NGX_STREAM_UPS_CONF|NGX_CONF_1MORE,
          ngx_stream_upstream_check,
          0,
          0,
          NULL },

        { ngx_string("check_keepalive_requests"),
          NGX_STREAM_UPS_CONF|NGX_CONF_TAKE1,
          ngx_stream_upstream_check_keepalive_requests,
          0,
          0,
          NULL },

        { ngx_string("check_http_send"),
          NGX_STREAM_UPS_CONF|NGX_CONF_TAKE1,
          ngx_stream_upstream_check_http_send,
          0,
          0,
          NULL },

        { ngx_string("check_http_expect_alive"),
          NGX_STREAM_UPS_CONF|NGX_CONF_1MORE,
          ngx_stream_upstream_check_http_expect_alive,
          0,
          0,
          NULL },


        { ngx_string("check_shm_size"),
          NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
          ngx_stream_upstream_check_shm_size,
          0,
          0,
          NULL },

        ngx_null_command
};

static ngx_stream_module_t  ngx_stream_upstream_check_module_ctx = {
        NULL,                                    /* preconfiguration */
        NULL,                                    /* postconfiguration */

        ngx_stream_upstream_check_create_main_conf,/* create main configuration */
        ngx_stream_upstream_check_init_main_conf,  /* init main configuration */

        ngx_stream_upstream_check_create_srv_conf, /* create server configuration */
        NULL                                    /* merge server configuration */

};


ngx_module_t  ngx_stream_upstream_check_module = {
        NGX_MODULE_V1,
        &ngx_stream_upstream_check_module_ctx,   /* module context */
        ngx_stream_upstream_check_commands,      /* module directives */
        NGX_STREAM_MODULE,                       /* module type */
        NULL,                                  /* init master */
        NULL,                                  /* init module */
        ngx_stream_upstream_check_init_process,  /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};



static ngx_check_conf_t  ngx_check_types[] = {

        { NGX_CHECK_TYPE_TCP,
                ngx_string("tcp"),
                ngx_null_string,
                0,
                ngx_stream_upstream_check_peek_handler,
                ngx_stream_upstream_check_peek_handler,
                NULL,
                NULL,
                NULL,
                0,   //zhoucx: need_pool ? no, we just connect peer.
                0 }, //zhoucx: need_keepalive ? i change it to no
        { NGX_CHECK_TYPE_UDP,
                ngx_string("udp"),
                ngx_string("X"),/* zhoucx: default send data.
                                 (we must send some data and then call recv to trigger icmp error response).*/
                0,
                ngx_stream_upstream_check_send_handler,
                ngx_stream_upstream_check_peek_handler,
                ngx_stream_upstream_check_http_init,
                NULL,
                ngx_stream_upstream_check_http_reinit,
                1,    // (changxun): when send data, we need pool
                0 },
        { NGX_CHECK_TYPE_HTTP,
                ngx_string("http"),
                ngx_string("GET / HTTP/1.0\r\n\r\n"),
                NGX_CONF_BITMASK_SET | NGX_CHECK_HTTP_2XX | NGX_CHECK_HTTP_3XX,
                ngx_stream_upstream_check_send_handler,
                ngx_stream_upstream_check_recv_handler,
                ngx_stream_upstream_check_http_init,
                ngx_stream_upstream_check_http_parse,
                ngx_stream_upstream_check_http_reinit,
                1,
                1 },

        { 0,
                ngx_null_string,
                ngx_null_string,
                0,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                0,
                0 }
};

/* external glabal var*/
 ngx_uint_t ngx_stream_upstream_check_shm_generation = 0; //reload counter
 ngx_upstream_check_peers_t *stream_peers_ctx = NULL; //need by check status module


ngx_uint_t
ngx_stream_upstream_check_add_peer(ngx_conf_t *cf,
                                   ngx_stream_upstream_srv_conf_t *us, ngx_addr_t *peer_addr)
{
    ngx_upstream_check_peer_t       *peer;
    ngx_upstream_check_peers_t      *peers;
    ngx_upstream_check_srv_conf_t   *ucscf;
    ngx_stream_upstream_check_main_conf_t  *ucmcf;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                      "[ngx-healthcheck][stream][api] add a peer:( %V ) to health check list.",
                      &peer_addr->name);

    if (us->srv_conf == NULL) {
        return NGX_ERROR;
    }

    ucscf = ngx_stream_conf_upstream_srv_conf(us, ngx_stream_upstream_check_module);

    if(ucscf->check_interval == 0) {
        return NGX_ERROR;
    }
    
    ucmcf = ngx_stream_conf_get_module_main_conf(cf,
                                               ngx_stream_upstream_check_module);
    peers = ucmcf->peers;

    peer = ngx_array_push(&peers->peers);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(peer, sizeof(ngx_upstream_check_peer_t));

    peer->index = peers->peers.nelts - 1;
    peer->conf = ucscf;
    peer->upstream_name = &us->host;
    peer->peer_addr = peer_addr;

    if (ucscf->port) {
        peer->check_peer_addr = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
        if (peer->check_peer_addr == NULL) {
            return NGX_ERROR;
        }

        if (ngx_stream_upstream_check_addr_change_port(cf->pool,
                                                       peer->check_peer_addr, peer_addr, ucscf->port)
            != NGX_OK) {

            return NGX_ERROR;
        }

    } else {
        peer->check_peer_addr = peer->peer_addr;
    }

    peers->checksum +=
            ngx_murmur_hash2(peer_addr->name.data, peer_addr->name.len);

    return peer->index;
}


static ngx_int_t
ngx_stream_upstream_check_addr_change_port(ngx_pool_t *pool, ngx_addr_t *dst,
                                           ngx_addr_t *src, ngx_uint_t port)
{
    size_t                len;
    u_char               *p;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    dst->socklen = src->socklen;
    dst->sockaddr = ngx_palloc(pool, dst->socklen);
    if (dst->sockaddr == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->sockaddr, src->sockaddr, dst->socklen);

    switch (dst->sockaddr->sa_family) {

        case AF_INET:

            len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
            sin = (struct sockaddr_in *) dst->sockaddr;
            sin->sin_port = htons(port);

            break;

#if (NGX_HAVE_INET6)
        case AF_INET6:

        len = NGX_INET6_ADDRSTRLEN + sizeof(":65535") - 1;
        sin6 = (struct sockaddr_in6 *) dst->sockaddr;
        sin6->sin6_port = htons(port);

        break;
#endif

        default:
            return NGX_ERROR;
    }

    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

#if (nginx_version >= 1005012)
    len = ngx_sock_ntop(dst->sockaddr, dst->socklen, p, len, 1);
#else
    len = ngx_sock_ntop(dst->sockaddr, p, len, 1);
#endif

    dst->name.len = len;
    dst->name.data = p;

    return NGX_OK;
}


ngx_uint_t
ngx_stream_upstream_check_peer_down(ngx_uint_t index)
{
    ngx_upstream_check_peer_t  *peer;

    if (stream_peers_ctx == NULL || index >= stream_peers_ctx->peers.nelts) {
        return 0;
    }

    peer = stream_peers_ctx->peers.elts;

    return (peer[index].shm->down);
}


/* TODO: this interface can count each peer's busyness */
void
ngx_stream_upstream_check_get_peer(ngx_uint_t index)
{
    ngx_upstream_check_peer_t  *peer;

    if (stream_peers_ctx == NULL || index >= stream_peers_ctx->peers.nelts) {
        return;
    }

    peer = stream_peers_ctx->peers.elts;

    ngx_shmtx_lock(&peer[index].shm->mutex);

    peer[index].shm->busyness++;
    peer[index].shm->access_count++;

    ngx_shmtx_unlock(&peer[index].shm->mutex);
}


void
ngx_stream_upstream_check_free_peer(ngx_uint_t index)
{
    ngx_upstream_check_peer_t  *peer;

    if (stream_peers_ctx == NULL || index >= stream_peers_ctx->peers.nelts) {
        return;
    }

    peer = stream_peers_ctx->peers.elts;

    ngx_shmtx_lock(&peer[index].shm->mutex);

    if (peer[index].shm->busyness > 0) {
        peer[index].shm->busyness--;
    }

    ngx_shmtx_unlock(&peer[index].shm->mutex);
}


static ngx_int_t
ngx_stream_upstream_check_add_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t                           i;
    ngx_msec_t                           t, delay;
    ngx_check_conf_t                    *cf;
    ngx_upstream_check_peer_t      *peer;
    ngx_upstream_check_peers_t     *peers;
    ngx_upstream_check_srv_conf_t  *ucscf;
    ngx_upstream_check_peer_shm_t  *peer_shm;
    ngx_upstream_check_peers_shm_t *peers_shm;

    peers = stream_peers_ctx;
    if (peers == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                     "[ngx-healthcheck][stream][timers] no stream section, skip init");
        return NGX_OK;
    }

    peers_shm = peers->peers_shm;
    if (peers_shm == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                     "[ngx-healthcheck][stream][timers][when init process]"
                     "no peers, so skip add timers");
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                   "[ngx-healthcheck][stream][timers][when init process]"
                   "start check-timer for %ud peers",
                   peers->peers.nelts);

    srandom(ngx_pid);

    peer = peers->peers.elts;
    peer_shm = peers_shm->peers;

    for (i = 0; i < peers->peers.nelts; i++) {
        peer[i].shm = &peer_shm[i];

        peer[i].check_ev.handler = 
                ngx_stream_upstream_check_begin_handler;
        peer[i].check_ev.log = cycle->log;
        peer[i].check_ev.data = &peer[i];
        peer[i].check_ev.timer_set = 0;

        peer[i].check_timeout_ev.handler =
                ngx_stream_upstream_check_timeout_handler;
        peer[i].check_timeout_ev.log = cycle->log;
        peer[i].check_timeout_ev.data = &peer[i];
        peer[i].check_timeout_ev.timer_set = 0;

        ucscf = peer[i].conf;
        cf = ucscf->check_type_conf;

        if (cf->need_pool) {
            peer[i].pool = ngx_create_pool(ngx_pagesize, cycle->log);
            if (peer[i].pool == NULL) {
                return NGX_ERROR;
            }
        }

        peer[i].send_handler = cf->send_handler;
        peer[i].recv_handler = cf->recv_handler;

        peer[i].init = cf->init;
        peer[i].parse = cf->parse;
        peer[i].reinit = cf->reinit;

        /*
         * We add a random start time here, since we don't want to trigger
         * the check events too close to each other at the beginning.
         */
        // ensure interval >= 1000ms.
        delay = ucscf->check_interval > 1000 ? ucscf->check_interval : 1000;
        t = ngx_random() % delay; // t in range(0~999 ms)

        ngx_add_timer(&peer[i].check_ev, t);
    }

    return NGX_OK;
}


static void
ngx_stream_upstream_check_begin_handler(ngx_event_t *event)
{
    ngx_msec_t                           interval;
    ngx_upstream_check_peer_t      *peer;
    ngx_upstream_check_peers_t     *peers;
    ngx_upstream_check_srv_conf_t  *ucscf;
    ngx_upstream_check_peers_shm_t *peers_shm;


    peers = stream_peers_ctx;
    if (peers == NULL) {
        return;
    }

    peers_shm = peers->peers_shm;
    if (peers_shm == NULL) {
        return;
    }

    peer = event->data;
    ucscf = peer->conf;

    if (ngx_stream_upstream_check_need_exit()) {
        ngx_log_error(NGX_LOG_NOTICE, event->log, 0,
                   "[ngx-healthcheck][stream][check-handler][when begin check]"
                   "recv exit signal, skip current check for peer:(%V)", 
                   &peer->check_peer_addr->name);
        return;
    }

    ngx_add_timer(event, ucscf->check_interval / 2);//zhoucx: what's mean?

    /* This process is processing this peer now. */
    if ((peer->shm->owner == ngx_pid  ||
         (peer->pc.connection != NULL) ||
         peer->check_timeout_ev.timer_set)) {
        return;
    }

    interval = ngx_current_msec - peer->shm->access_time;
    ngx_log_debug6(NGX_LOG_DEBUG_STREAM, event->log, 0,
                   "stream check begin handler for (%V): index: %ui, owner: %P, "
                           "ngx_pid: %P, current interval: %M, check_interval: %M",
                   &peer->check_peer_addr->name, peer->index, peer->shm->owner,
                   ngx_pid, interval,
                   ucscf->check_interval);

    ngx_shmtx_lock(&peer->shm->mutex);

    if (peers_shm->generation != ngx_stream_upstream_check_shm_generation) {
        ngx_shmtx_unlock(&peer->shm->mutex);
        return;
    }

    if ((interval >= ucscf->check_interval)
        && (peer->shm->owner == NGX_INVALID_PID))
    {
        peer->shm->owner = ngx_pid;

    } else if (interval >= (ucscf->check_interval << 4)) {

        /*
         * If the check peer has been untouched for 2^4 times of
         * the check interval, activate the current timer.
         * Sometimes, the checking process may disappear
         * in some circumstances, and the clean event will never
         * be triggered.
         */
        peer->shm->owner = ngx_pid;
        peer->shm->access_time = ngx_current_msec;
    }

    ngx_shmtx_unlock(&peer->shm->mutex);

    if (peer->shm->owner == ngx_pid) {
        ngx_log_error(NGX_LOG_INFO, event->log, 0,
                   "[ngx-healthcheck][stream][check-event][when begin check]"
                   "restart a check for peer:(%V)", 
                   &peer->check_peer_addr->name);
        ngx_stream_upstream_check_connect_handler(event);
    }
}


static void
ngx_stream_upstream_check_connect_handler(ngx_event_t *event)
{
    ngx_int_t                            rc;
    ngx_connection_t                    *c;
    ngx_upstream_check_peer_t      *peer;
    ngx_upstream_check_srv_conf_t  *ucscf;

    peer = event->data;
    ucscf = peer->conf;

    if (ngx_stream_upstream_check_need_exit()) {
        ngx_log_error(NGX_LOG_NOTICE, event->log, 0,
                   "[ngx-healthcheck][stream][check-handler][when connect peer]"
                   "recv exit signal, skip current check for peer:(%V)", 
                   &peer->check_peer_addr->name);
        return;
    }

    if (peer->pc.connection != NULL) {
        c = peer->pc.connection;
        if ((rc = ngx_stream_upstream_check_peek_one_byte(c)) == NGX_OK) {
            goto upstream_check_connect_done;
        } else {
            ngx_close_connection(c);
            peer->pc.connection = NULL;
        }
    }
    ngx_memzero(&peer->pc, sizeof(ngx_peer_connection_t));

    peer->pc.sockaddr = peer->check_peer_addr->sockaddr;
    peer->pc.socklen = peer->check_peer_addr->socklen;
    peer->pc.name = &peer->check_peer_addr->name;
    peer->pc.type = (ucscf->check_type_conf->type==NGX_CHECK_TYPE_UDP)?SOCK_DGRAM:SOCK_STREAM;

    peer->pc.get = ngx_event_get_peer;
    peer->pc.log = event->log;
    peer->pc.log_error = NGX_ERROR_ERR;

    peer->pc.cached = 0;
    peer->pc.connection = NULL;

    rc = ngx_event_connect_peer(&peer->pc); // (changxun): noblocking .

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_stream_upstream_check_status_update(peer, 0); //set down
        return;
    }

    /* NGX_OK or NGX_AGAIN */
    c = peer->pc.connection;
    c->data = peer;
    c->log = peer->pc.log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->pool = peer->pool;

    /* (changxun): set sock opt "IP_RECVERR" in order to recv icmp error like host/port unreachable. */
    int val = 1;
    if( setsockopt( c->fd, SOL_IP, IP_RECVERR, &val, sizeof(val) ) == -1 ){
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
              "setsockopt(IP_RECVERR) failed with peer: %V ",
              &peer->check_peer_addr->name);
    }

    upstream_check_connect_done:
    peer->state = NGX_HTTP_CHECK_CONNECT_DONE;

    c->write->handler = peer->send_handler;
    c->read->handler = peer->recv_handler;

    ngx_add_timer(&peer->check_timeout_ev, ucscf->check_timeout);//zhoucx: start connect timeout timer.

    /* The kqueue's loop interface needs it. */
    if (rc == NGX_OK) {
        c->write->handler(c->write); //zhoucx: it is check_type->send_handler.
    }
}

static ngx_int_t
ngx_stream_upstream_check_peek_one_byte(ngx_connection_t *c)
{
    char                            buf[1];
    ngx_int_t                       n;
    ngx_err_t                       err;

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = ngx_socket_errno;

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                   "[ngx-healthcheck][stream] when recv one byte,"
                   " recv(): %i, fd: %d",
                   n, c->fd);

    if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}

static void
ngx_stream_upstream_check_peek_handler(ngx_event_t *event)
{
    ngx_connection_t               *c;
    ngx_upstream_check_peer_t *peer;

    if (ngx_stream_upstream_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    if (ngx_stream_upstream_check_peek_one_byte(c) == NGX_OK) {
        ngx_stream_upstream_check_status_update(peer, 1); //up

    } else {
        c->error = 1;
        ngx_stream_upstream_check_status_update(peer, 0); //down
    }

    ngx_stream_upstream_check_clean_event(peer);

    ngx_stream_upstream_check_finish_handler(event);
}


static void
ngx_stream_upstream_check_discard_handler(ngx_event_t *event)
{
    u_char                          buf[4096];
    ssize_t                         size;
    ngx_connection_t               *c;
    ngx_upstream_check_peer_t *peer;

    c = event->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "upstream check discard handler");

    if (ngx_stream_upstream_check_need_exit()) {
        return;
    }

    peer = c->data;

    while (1) {
        size = c->recv(c, buf, 4096);

        if (size > 0) {
            continue;

        } else if (size == NGX_AGAIN) {
            break;

        } else {
            if (size == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                               "peer closed its half side of the connection");
            }

            goto check_discard_fail;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto check_discard_fail;
    }

    return;

    check_discard_fail:
    c->error = 1;
    ngx_stream_upstream_check_clean_event(peer);
}


static void
ngx_stream_upstream_check_dummy_handler(ngx_event_t *event)
{
    return;
}


static void
ngx_stream_upstream_check_send_handler(ngx_event_t *event)
{
    ssize_t                         size;
    ngx_connection_t               *c;
    ngx_stream_upstream_check_ctx_t  *ctx;
    ngx_upstream_check_peer_t *peer;

    if (ngx_stream_upstream_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                     "[ngx-healthcheck][stream][send-handler] for peer:%V",
                     &peer->check_peer_addr->name);

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "check pool NULL with peer: %V ",
                      &peer->check_peer_addr->name);

        goto check_send_fail;
    }

    if (peer->state != NGX_HTTP_CHECK_CONNECT_DONE) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "check handle write event error with peer: %V ",
                          &peer->check_peer_addr->name);

            goto check_send_fail;
        }

        return; // (changxun): wait future connect event.
    }

    if (peer->check_data == NULL) {

        peer->check_data = ngx_pcalloc(peer->pool,
                                       sizeof(ngx_stream_upstream_check_ctx_t));
        if (peer->check_data == NULL) {
            goto check_send_fail;
        }

        if (peer->init == NULL || peer->init(peer) != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "check init error with peer: %V ",
                          &peer->check_peer_addr->name);

            goto check_send_fail;
        }
    }

    ctx = peer->check_data;

    while (ctx->send.pos < ctx->send.last) {
        /* send check data */
        size = c->send(c, ctx->send.pos, ctx->send.last - ctx->send.pos);

        {
        ngx_err_t  err;

        err = (size >=0) ? 0 : ngx_socket_errno;
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,
                       "[ngx-healthcheck][stream][send-handler]" 
                       "send check data size: %z, total: %z for peer:%V",
                       size, ctx->send.last - ctx->send.pos, &peer->check_peer_addr->name);
        }

        if (size > 0) {
            ctx->send.pos += size;
        } else if (size == 0 || size == NGX_AGAIN) {
            return;
        } else {
            c->error = 1;
            goto check_send_fail;
        }
    }

    if (ctx->send.pos == ctx->send.last) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                     "[ngx-healthcheck][stream][send-handler] send finish for peer:%V",
                     &peer->check_peer_addr->name);
        peer->state = NGX_HTTP_CHECK_SEND_DONE;
        c->requests++;
    }

    return; // normal return;

    check_send_fail:
    ngx_stream_upstream_check_status_update(peer, 0);
    ngx_stream_upstream_check_clean_event(peer);
}


static void
ngx_stream_upstream_check_recv_handler(ngx_event_t *event)
{
    u_char                         *new_buf;
    ssize_t                         size, n;
    ngx_int_t                       rc;
    ngx_connection_t               *c;
    ngx_stream_upstream_check_ctx_t  *ctx;
    ngx_upstream_check_peer_t *peer;

    if (ngx_stream_upstream_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    if (peer->state != NGX_HTTP_CHECK_SEND_DONE) {

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto check_recv_fail;
        }

        return;
    }

    ctx = peer->check_data;

    if (ctx->recv.start == NULL) {
        /* 1/2 of the page_size, is it enough? */
        ctx->recv.start = ngx_palloc(c->pool, ngx_pagesize / 2);
        if (ctx->recv.start == NULL) {
            goto check_recv_fail;
        }

        ctx->recv.last = ctx->recv.pos = ctx->recv.start;
        ctx->recv.end = ctx->recv.start + ngx_pagesize / 2;
    }

    while (1) {
        n = ctx->recv.end - ctx->recv.last;

        /* buffer not big enough? enlarge it by twice */
        if (n == 0) {
            size = ctx->recv.end - ctx->recv.start;
            new_buf = ngx_palloc(c->pool, size * 2);
            if (new_buf == NULL) {
                goto check_recv_fail;
            }

            ngx_memcpy(new_buf, ctx->recv.start, size);

            ctx->recv.pos = ctx->recv.start = new_buf;
            ctx->recv.last = new_buf + size;
            ctx->recv.end = new_buf + size * 2;

            n = ctx->recv.end - ctx->recv.last;
        }

        size = c->recv(c, ctx->recv.last, n);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, err,
                       "stream check recv size: %z, peer: %V ",
                       size, &peer->check_peer_addr->name);
        }
#endif

        if (size > 0) {
            ctx->recv.last += size;
            continue;
        } else if (size == 0 || size == NGX_AGAIN) {
            break;
        } else {
            c->error = 1;
            goto check_recv_fail;
        }
    }

    rc = peer->parse(peer);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream check parse rc: %i, peer: %V ",
                   rc, &peer->check_peer_addr->name);

    switch (rc) {

        case NGX_AGAIN:
            /* The peer has closed its half side of the connection. */
            if (size == 0) {
                ngx_stream_upstream_check_status_update(peer, 0); //down
                c->error = 1;
                break;
            }

            return;

        case NGX_ERROR:
            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "check protocol %V error with peer: %V ",
                          &peer->conf->check_type_conf->name,
                          &peer->check_peer_addr->name);

            ngx_stream_upstream_check_status_update(peer, 0); // (changxun): set down
            break;

        case NGX_OK:
            /* fall through */

        default:
            ngx_stream_upstream_check_status_update(peer, 1); // (changxun): set up
            break;
    }

    peer->state = NGX_HTTP_CHECK_RECV_DONE;
    ngx_stream_upstream_check_clean_event(peer);
    return;

    check_recv_fail:
    ngx_stream_upstream_check_status_update(peer, 0); //down
    ngx_stream_upstream_check_clean_event(peer);
}


static ngx_int_t
ngx_stream_upstream_check_http_init(ngx_upstream_check_peer_t *peer)
{
    ngx_stream_upstream_check_ctx_t       *ctx;
    ngx_upstream_check_srv_conf_t  *ucscf;

    ctx = peer->check_data;
    ucscf = peer->conf;

    ctx->send.start = ctx->send.pos = (u_char *)ucscf->send.data;
    ctx->send.end = ctx->send.last = ctx->send.start + ucscf->send.len;

    ctx->recv.start = ctx->recv.pos = NULL;
    ctx->recv.end = ctx->recv.last = NULL;

    ctx->state = 0;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_check_http_parse(ngx_upstream_check_peer_t *peer)
{
    ngx_int_t                            rc;
    ngx_uint_t                           code, code_n;
    ngx_stream_upstream_check_ctx_t       *ctx;
    ngx_upstream_check_srv_conf_t  *ucscf;

    ucscf = peer->conf;
    ctx = peer->check_data;

    if ((ctx->recv.last - ctx->recv.pos) > 0) {

        rc = ngx_stream_upstream_check_parse_status_line(ctx,
                                                         &ctx->recv,
                                                         &ctx->status);
        if (rc == NGX_AGAIN) {
            return rc;
        }

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "http parse status line error with peer: %V ",
                          &peer->check_peer_addr->name);
            return rc;
        }

        code = ctx->status.code;

        if (code >= 200 && code < 300) {
            code_n = NGX_CHECK_HTTP_2XX;
        } else if (code >= 300 && code < 400) {
            code_n = NGX_CHECK_HTTP_3XX;
        } else if (code >= 400 && code < 500) {
            peer->pc.connection->error = 1;
            code_n = NGX_CHECK_HTTP_4XX;
        } else if (code >= 500 && code < 600) {
            peer->pc.connection->error = 1;
            code_n = NGX_CHECK_HTTP_5XX;
        } else {
            peer->pc.connection->error = 1;
            code_n = NGX_CHECK_HTTP_ERR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
                       "http_parse: code_n: %ui, conf: %ui",
                       code_n, ucscf->code.status_alive);

        if (code_n & ucscf->code.status_alive) {
            return NGX_OK;
        } else {
            return NGX_ERROR;
        }
    } else {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_check_parse_status_line(ngx_stream_upstream_check_ctx_t *ctx,
                                            ngx_buf_t *b, ngx_http_status_t *status)
{
    u_char ch, *p;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

            /* "HTTP/" */
            case sw_start:
                if (ch != 'H') {
                    return NGX_ERROR;
                }

                state = sw_H;
                break;

            case sw_H:
                if (ch != 'T') {
                    return NGX_ERROR;
                }

                state = sw_HT;
                break;

            case sw_HT:
                if (ch != 'T') {
                    return NGX_ERROR;
                }

                state = sw_HTT;
                break;

            case sw_HTT:
                if (ch != 'P') {
                    return NGX_ERROR;
                }

                state = sw_HTTP;
                break;

            case sw_HTTP:
                if (ch != '/') {
                    return NGX_ERROR;
                }

                state = sw_first_major_digit;
                break;

                /* the first digit of major HTTP version */
            case sw_first_major_digit:
                if (ch < '1' || ch > '9') {
                    return NGX_ERROR;
                }

                state = sw_major_digit;
                break;

                /* the major HTTP version or dot */
            case sw_major_digit:
                if (ch == '.') {
                    state = sw_first_minor_digit;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NGX_ERROR;
                }

                break;

                /* the first digit of minor HTTP version */
            case sw_first_minor_digit:
                if (ch < '0' || ch > '9') {
                    return NGX_ERROR;
                }

                state = sw_minor_digit;
                break;

                /* the minor HTTP version or the end of the request line */
            case sw_minor_digit:
                if (ch == ' ') {
                    state = sw_status;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NGX_ERROR;
                }

                break;

                /* HTTP status code */
            case sw_status:
                if (ch == ' ') {
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NGX_ERROR;
                }

                status->code = status->code * 10 + ch - '0';

                if (++status->count == 3) {
                    state = sw_space_after_status;
                    status->start = p - 2;
                }

                break;

                /* space or end of line */
            case sw_space_after_status:
                switch (ch) {
                    case ' ':
                        state = sw_status_text;
                        break;
                    case '.':                    /* IIS may send 403.1, 403.2, etc */
                        state = sw_status_text;
                        break;
                    case CR:
                        state = sw_almost_done;
                        break;
                    case LF:
                        goto done;
                    default:
                        return NGX_ERROR;
                }
                break;

                /* any text until end of line */
            case sw_status_text:
                switch (ch) {
                    case CR:
                        state = sw_almost_done;

                        break;
                    case LF:
                        goto done;
                }
                break;

                /* end of status line */
            case sw_almost_done:
                status->end = p - 1;
                if (ch == LF) {
                    goto done;
                } else {
                    return NGX_ERROR;
                }
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

    done:

    b->pos = p + 1;

    if (status->end == NULL) {
        status->end = p;
    }

    ctx->state = sw_start;

    return NGX_OK;
}


static void
ngx_stream_upstream_check_http_reinit(ngx_upstream_check_peer_t *peer)
{
    ngx_stream_upstream_check_ctx_t  *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;

    ctx->state = 0;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));
}


static void
ngx_stream_upstream_check_status_update(ngx_upstream_check_peer_t *peer,
                                        ngx_int_t result)
{
    ngx_upstream_check_srv_conf_t  *ucscf;

    ucscf = peer->conf;

    if (result) { //up
        peer->shm->rise_count++;
        peer->shm->fall_count = 0;
        if (peer->shm->down && peer->shm->rise_count >= ucscf->rise_count) {
            peer->shm->down = 0;
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "[ngx-healthcheck][stream][status-update]"
                          " change status to UP for peer: %V ",
                          &peer->check_peer_addr->name);
        }
    } else {
        peer->shm->rise_count = 0;
        peer->shm->fall_count++;
        if (!peer->shm->down && peer->shm->fall_count >= ucscf->fall_count) {
            peer->shm->down = 1;
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "[ngx-healthcheck][stream][status-update]"
                          " change status to DOWN for peer: %V ",
                          &peer->check_peer_addr->name);
        }
    }

    peer->shm->access_time = ngx_current_msec;
}


static void
ngx_stream_upstream_check_clean_event(ngx_upstream_check_peer_t *peer)
{
    ngx_connection_t                    *c;
    ngx_upstream_check_srv_conf_t  *ucscf;
    ngx_check_conf_t                    *cf;

    c = peer->pc.connection;
    ucscf = peer->conf;
    cf = ucscf->check_type_conf;

    if (c) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream check clean event: index:%i, fd: %d",
                       peer->index, c->fd);
        if (c->error == 0 &&
            cf->need_keepalive &&
            (c->requests < ucscf->check_keepalive_requests))
        {
            c->write->handler = ngx_stream_upstream_check_dummy_handler;
            c->read->handler = ngx_stream_upstream_check_discard_handler;
        } else {
            ngx_close_connection(c);
            peer->pc.connection = NULL;
        }
    }

    if (peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&peer->check_timeout_ev);
    }

    peer->state = NGX_HTTP_CHECK_ALL_DONE;

    if (peer->check_data != NULL && peer->reinit) {
        peer->reinit(peer);
    }

    peer->shm->owner = NGX_INVALID_PID;
}


static void
ngx_stream_upstream_check_timeout_handler(ngx_event_t *event)
{
    ngx_upstream_check_peer_t  *peer;

    if (ngx_stream_upstream_check_need_exit()) {
        return;
    }

    peer = event->data;

    if(peer->pc.type == SOCK_STREAM){
        peer->pc.connection->error = 1;
    
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
              "[ngx-healthcheck][stream][timers][timeout]"
              "tcp check time out with peer: %V ,set it down.",
              &peer->check_peer_addr->name);
    
        ngx_stream_upstream_check_status_update(peer, 0);
    }else if(peer->pc.type == SOCK_DGRAM){
        peer->pc.connection->error = 0;
    
        ngx_log_error(NGX_LOG_INFO, event->log, 0,
              "[ngx-healthcheck][stream][timers][timeout]"
              "udp check time out with peer: %V, we assum it's up :) ",
              &peer->check_peer_addr->name);
    
        ngx_stream_upstream_check_status_update(peer, 1);
    }

    ngx_stream_upstream_check_clean_event(peer);
}


static void
ngx_stream_upstream_check_finish_handler(ngx_event_t *event)
{
    if (ngx_stream_upstream_check_need_exit()) {
        return;
    }
}


static ngx_int_t
ngx_stream_upstream_check_need_exit()
{
    if (ngx_terminate || ngx_exiting || ngx_quit) {
        ngx_stream_upstream_check_clear_all_events();
        return 1;
    }

    return 0;
}


static void
ngx_stream_upstream_check_clear_all_events()
{
    ngx_uint_t                       i;
    ngx_connection_t                *c;
    ngx_upstream_check_peer_t  *peer;
    ngx_upstream_check_peers_t *peers;

    static ngx_flag_t                has_cleared = 0; // note: this static var.

    if (has_cleared || stream_peers_ctx == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "clear all the events on %P ", ngx_pid);

    has_cleared = 1;

    peers = stream_peers_ctx;

    peer = peers->peers.elts;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (peer[i].check_ev.timer_set) {
            ngx_del_timer(&peer[i].check_ev);
        }

        if (peer[i].check_timeout_ev.timer_set) {
            ngx_del_timer(&peer[i].check_timeout_ev);
        }

        c = peer[i].pc.connection;
        if (c) {
            ngx_close_connection(c);
            peer[i].pc.connection = NULL;
        }

        if (peer[i].pool != NULL) {
            ngx_destroy_pool(peer[i].pool);
            peer[i].pool = NULL;
        }
    }
}


static ngx_check_conf_t *
ngx_http_get_check_type_conf(ngx_str_t *str)
{
    ngx_uint_t  i;

    for (i = 0;  ; i++) {

        if (ngx_check_types[i].type == 0) {
            break;
        }

        if (str->len != ngx_check_types[i].name.len) {
            continue;
        }

        if (ngx_strncmp(str->data, ngx_check_types[i].name.data,
                        str->len) == 0)
        {
            return &ngx_check_types[i];
        }
    }

    return NULL;
}

static char * 
ngx_stream_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value, s;
    ngx_uint_t                           i, port, rise, fall, default_down;
    ngx_msec_t                           interval, timeout;
    ngx_upstream_check_srv_conf_t  *ucscf;

    /* default values */
    port = 0;
    rise = 2;
    fall = 5;
    interval = 30000;
    timeout = 1000;
    default_down = 1;

    value = cf->args->elts;

    ucscf = ngx_stream_conf_get_module_srv_conf(cf,
                                              ngx_stream_upstream_check_module);
    if (ucscf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            ucscf->check_type_conf = ngx_http_get_check_type_conf(&s);

            if (ucscf->check_type_conf == NULL) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "port=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            port = ngx_atoi(s.data, s.len);
            if (port == (ngx_uint_t) NGX_ERROR || port == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            interval = ngx_atoi(s.data, s.len);
            if (interval == (ngx_msec_t) NGX_ERROR || interval == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = ngx_atoi(s.data, s.len);
            if (timeout == (ngx_msec_t) NGX_ERROR || timeout == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            rise = ngx_atoi(s.data, s.len);
            if (rise == (ngx_uint_t) NGX_ERROR || rise == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fall=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            fall = ngx_atoi(s.data, s.len);
            if (fall == (ngx_uint_t) NGX_ERROR || fall == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "default_down=", 13) == 0) {
            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            if (ngx_strcasecmp(s.data, (u_char *) "true") == 0) {
                default_down = 1;
            } else if (ngx_strcasecmp(s.data, (u_char *) "false") == 0) {
                default_down = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%s\", "
                                           "it must be \"true\" or \"false\"",
                                   value[i].data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        goto invalid_check_parameter;
    }

    ucscf->port = port;
    ucscf->check_interval = interval;
    ucscf->check_timeout = timeout;
    ucscf->fall_count = fall;
    ucscf->rise_count = rise;
    ucscf->default_down = default_down;

    if (ucscf->check_type_conf == NGX_CONF_UNSET_PTR) {
        ngx_str_set(&s, "tcp"); //zhoucx: default check type is "tcp".
        ucscf->check_type_conf = ngx_http_get_check_type_conf(&s);
    }

    ngx_conf_log_error(NGX_LOG_NOTICE /* current level always it */, cf, 0,
                       "[ngx-healthcheck][stream][directive] found check arg:"
                       "[port:%d,interval:%d,timeout:%d,fall:%d,rise:%d,default_down:%d]", 
                       port,interval,timeout,rise,default_down);
    return NGX_CONF_OK;

    invalid_check_parameter:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_stream_upstream_check_keepalive_requests(ngx_conf_t *cf, ngx_command_t *cmd,
                                             void *conf)
{
    ngx_str_t                           *value;
    ngx_upstream_check_srv_conf_t  *ucscf;
    ngx_uint_t                           requests;

    value = cf->args->elts;

    ucscf = ngx_stream_conf_get_module_srv_conf(cf,
                                              ngx_stream_upstream_check_module);

    requests = ngx_atoi(value[1].data, value[1].len);
    if (requests == (ngx_uint_t) NGX_ERROR || requests == 0) {
        return "invalid value";
    }

    ucscf->check_keepalive_requests = requests;

    return NGX_CONF_OK;
}


static char *
ngx_stream_upstream_check_http_send(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf)
{
    ngx_str_t                           *value;
    ngx_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;

    ucscf = ngx_stream_conf_get_module_srv_conf(cf,
                                              ngx_stream_upstream_check_module);

    ucscf->send = value[1];

    return NGX_CONF_OK;
}





static char *
ngx_stream_upstream_check_http_expect_alive(ngx_conf_t *cf, ngx_command_t *cmd,
                                            void *conf)
{
    ngx_str_t                           *value;
    ngx_uint_t                           bit, i, m;
    ngx_conf_bitmask_t                  *mask;
    ngx_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;
    mask = ngx_check_http_expect_alive_masks;

    ucscf = ngx_stream_conf_get_module_srv_conf(cf,
                                              ngx_stream_upstream_check_module);
    bit = ucscf->code.status_alive;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (bit & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                bit |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    ucscf->code.status_alive = bit;

    return NGX_CONF_OK;
}


static char *
ngx_stream_upstream_check_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                            *value;
    ngx_stream_upstream_check_main_conf_t  *ucmcf;

    ucmcf = ngx_stream_conf_get_module_main_conf(cf,
                                               ngx_stream_upstream_check_module);
    if (ucmcf->check_shm_size) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ucmcf->check_shm_size = ngx_parse_size(&value[1]);
    if (ucmcf->check_shm_size == (size_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}

//zhoucx: alloc memory for config struct.
static void *
ngx_stream_upstream_check_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_check_main_conf_t  *ucmcf;


    ucmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_check_main_conf_t));
    if (ucmcf == NULL) {
        return NULL;
    }

    ucmcf->peers = ngx_pcalloc(cf->pool,
                               sizeof(ngx_upstream_check_peers_t));
    if (ucmcf->peers == NULL) {
        return NULL;
    }

    ucmcf->peers->checksum = 0;

    if (ngx_array_init(&ucmcf->peers->peers, cf->pool, 16,
                       sizeof(ngx_upstream_check_peer_t)) != NGX_OK)
    {
        return NULL;
    }

    return ucmcf;
}


static char *
ngx_stream_upstream_check_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                      i;
    ngx_stream_upstream_srv_conf_t  **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    umcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_module);

    uscfp = umcf->upstreams.elts;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                       "[ngx-healthcheck][stream] when init main conf. upstreams num:%ui", 
                       umcf->upstreams.nelts);
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (ngx_stream_upstream_check_init_srv_conf(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_stream_upstream_check_init_shm(cf, conf);
}


static void *
ngx_stream_upstream_check_create_srv_conf(ngx_conf_t *cf)
{
    ngx_upstream_check_srv_conf_t  *ucscf;

    ucscf = ngx_pcalloc(cf->pool, sizeof(ngx_upstream_check_srv_conf_t));
    if (ucscf == NULL) {
        return NULL;
    }

    ucscf->port = NGX_CONF_UNSET_UINT;
    ucscf->fall_count = NGX_CONF_UNSET_UINT;
    ucscf->rise_count = NGX_CONF_UNSET_UINT;
    ucscf->check_timeout = NGX_CONF_UNSET_MSEC;
    ucscf->check_keepalive_requests = NGX_CONF_UNSET_UINT;
    ucscf->check_type_conf = NGX_CONF_UNSET_PTR;

    return ucscf;
}

static char *
ngx_stream_upstream_check_init_srv_conf(ngx_conf_t *cf, void *conf)
{
    ngx_check_conf_t                   *check;
    ngx_stream_upstream_srv_conf_t       *us = conf;
    ngx_upstream_check_srv_conf_t *ucscf;

    if (us->srv_conf == NULL) {
        return NGX_CONF_OK;
    }

    ucscf = ngx_stream_conf_upstream_srv_conf(us, ngx_stream_upstream_check_module);

    if (ucscf->port == NGX_CONF_UNSET_UINT) {
        ucscf->port = 0;
    }

    if (ucscf->fall_count == NGX_CONF_UNSET_UINT) {
        ucscf->fall_count = 2;
    }

    if (ucscf->rise_count == NGX_CONF_UNSET_UINT) {
        ucscf->rise_count = 5;
    }

    if (ucscf->check_interval == NGX_CONF_UNSET_MSEC) {
        ucscf->check_interval = 0;
    }

    if (ucscf->check_timeout == NGX_CONF_UNSET_MSEC) {
        ucscf->check_timeout = 1000;
    }

    if (ucscf->check_keepalive_requests == NGX_CONF_UNSET_UINT) {
        ucscf->check_keepalive_requests = 1;
    }

    if (ucscf->check_type_conf == NGX_CONF_UNSET_PTR) {
        ucscf->check_type_conf = NULL;
    }

    check = ucscf->check_type_conf;

    if (check) {
        //for http 
        if (ucscf->code.status_alive == 0) {
            ucscf->code.status_alive = check->default_status_alive;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_upstream_check_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_str_t                            *shm_name;
    ngx_uint_t                            shm_size;
    ngx_shm_zone_t                       *shm_zone;
    ngx_stream_upstream_check_main_conf_t  *ucmcf = conf;

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                       "[ngx-healthcheck][stream][init conf] init shm, total peers num:%ui", 
                       ucmcf->peers->peers.nelts); 
    if (1||(ucmcf->peers->peers.nelts > 0)) {

        ngx_stream_upstream_check_shm_generation++;

        shm_name = &ucmcf->peers->check_shm_name;

        ngx_stream_upstream_check_get_shm_name(shm_name, cf->pool,
                                               ngx_stream_upstream_check_shm_generation);

        /* The default check shared memory size is 1M */
        shm_size = 1 * 1024 * 1024;

        shm_size = shm_size < ucmcf->check_shm_size ?
                   ucmcf->check_shm_size : shm_size;

        shm_zone = ngx_shared_memory_add(cf, shm_name, shm_size,
                                         &ngx_stream_upstream_check_module);


        shm_zone->data = cf->pool;
        stream_peers_ctx = ucmcf->peers; //init global var: stream_peers_ctx obj.

        shm_zone->init = ngx_stream_upstream_check_init_shm_zone;
    }
    else {
        stream_peers_ctx = NULL;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_upstream_check_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool,
                                       ngx_uint_t generation)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, SHM_NAME_LEN, "%s#%ui",
                        "ngx_stream_upstream_check", generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_check_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                               size;
    ngx_str_t                            oshm_name;
    ngx_int_t                            rc;
    ngx_uint_t                           i, same, number;
    ngx_pool_t                          *pool;
    ngx_shm_zone_t                      *oshm_zone;
    ngx_slab_pool_t                     *shpool;
    ngx_upstream_check_peer_t      *peer;
    ngx_upstream_check_peers_t     *peers;
    ngx_upstream_check_srv_conf_t  *ucscf;
    ngx_upstream_check_peer_shm_t  *peer_shm, *opeer_shm;
    ngx_upstream_check_peers_shm_t *peers_shm, *opeers_shm;

    opeers_shm = NULL;
    peers_shm = NULL;
    ngx_str_null(&oshm_name);

    same = 0;


    ngx_log_error(NGX_LOG_INFO, shm_zone->shm.log, 0,
                  "[ngx-healthcheck][stream][shm_zone] init callback");

    peers = stream_peers_ctx;
    if (peers == NULL) {
        return NGX_OK;
    }

    number = peers->peers.nelts;

    pool = shm_zone->data;
    if (pool == NULL) {
        pool = ngx_cycle->pool;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    // alloc peers_shm
    size = sizeof(*peers_shm) +
           (number ) * sizeof(ngx_upstream_check_peer_shm_t);//last item not use :)
    peers_shm = ngx_slab_alloc(shpool, size);

    if (peers_shm == NULL) {
        goto failure;
    }
    ngx_memzero(peers_shm, size);

    peers_shm->generation = ngx_stream_upstream_check_shm_generation;
    peers_shm->checksum = peers->checksum;
    peers_shm->number = number;
    // end 

    if (data) {// ozone.data
        ngx_log_error(NGX_LOG_INFO, shm_zone->shm.log, 0,
                  "[ngx-healthcheck][stream][shm_zone] found old shm");
        opeers_shm = data;

        if ((opeers_shm->number == number)
            && (opeers_shm->checksum == peers->checksum)) {

            peers_shm = data;
            same = 1;
        }
    }

    if (!same) { 
        ngx_log_error(NGX_LOG_INFO, shm_zone->shm.log, 0,
                  "[ngx-healthcheck][stream][shm_zone] upstream data have changed.");

        if (ngx_stream_upstream_check_shm_generation > 1) {

            ngx_stream_upstream_check_get_shm_name(&oshm_name,
                                                   pool, ngx_stream_upstream_check_shm_generation - 1);

            /* The global variable ngx_cycle still points to the old one */
            oshm_zone = ngx_shared_memory_find((ngx_cycle_t *) ngx_cycle,
                                               &oshm_name,
                                               &ngx_stream_upstream_check_module);

            if (oshm_zone) {
                //normally, to here.
                opeers_shm = oshm_zone->data;

                ngx_log_error(NGX_LOG_INFO, shm_zone->shm.log, 0,
                               "stream upstream check, find oshm_zone:%p, "
                                       "opeers_shm: %p",
                               oshm_zone, opeers_shm);
            }
        }

    }// if (!same) { 


    peer = peers->peers.elts;

    for (i = 0; i < number; i++) {

        peer_shm = &peers_shm->peers[i];

        /*
         * This function may be triggered before the old stale
         * work process exits. The owner may stick to the old
         * pid.
         */
        peer_shm->owner = NGX_INVALID_PID;

        if (same) {
            continue;
        }

        peer_shm->socklen = peer[i].peer_addr->socklen;
        peer_shm->sockaddr = ngx_slab_alloc(shpool, peer_shm->socklen);
        if (peer_shm->sockaddr == NULL) {
            goto failure;
        }

        ngx_memcpy(peer_shm->sockaddr, peer[i].peer_addr->sockaddr,
                   peer_shm->socklen);

        if (opeers_shm) {

            opeer_shm = ngx_stream_upstream_check_find_shm_peer(opeers_shm,
                                                                peer[i].peer_addr, peer[i].upstream_name);
            if (opeer_shm) {
                //find opeer, copy status data.
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM, shm_zone->shm.log, 0,
                               "stream upstream check, inherit opeer: %V ",
                               &peer[i].peer_addr->name);

                rc = ngx_stream_upstream_check_init_shm_peer(peer_shm, opeer_shm,
                                                             0, pool, &peer[i].peer_addr->name, peer[i].upstream_name);
                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                continue; //next peer
            }
        }

        // init new peer status data.
        ucscf = peer[i].conf;
        rc = ngx_stream_upstream_check_init_shm_peer(peer_shm, NULL,
                                                     ucscf->default_down, pool,
                                                     &peer[i].peer_addr->name, peer[i].upstream_name);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    peers->peers_shm = peers_shm;
    shm_zone->data = peers_shm;

    return NGX_OK;

    failure:
    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                  "stream upstream check_shm_size is too small, "
                          "you should specify a larger size.");
    return NGX_ERROR;
}


static ngx_shm_zone_t *
ngx_shared_memory_find(ngx_cycle_t *cycle, ngx_str_t *name, void *tag)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = (ngx_list_part_t *) &(cycle->shared_memory.part);
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len) != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            continue;
        }

        return &shm_zone[i];
    }

    return NULL;
}


static ngx_upstream_check_peer_shm_t *
ngx_stream_upstream_check_find_shm_peer(ngx_upstream_check_peers_shm_t *p,
                                        ngx_addr_t *addr, ngx_str_t *upstream_name)
{
    ngx_uint_t                          i;
    ngx_upstream_check_peer_shm_t *peer_shm;

    for (i = 0; i < p->number; i++) {

        peer_shm = &p->peers[i];

        if (addr->socklen != peer_shm->socklen) {
            continue;
        }

        if (ngx_memcmp(addr->sockaddr, peer_shm->sockaddr, addr->socklen)) {
            continue;     
        }
		
	if (ngx_strcmp(upstream_name->data, peer_shm->upstream_name->data) == 0) {
	    return peer_shm;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_upstream_check_init_shm_peer(ngx_upstream_check_peer_shm_t *psh,
                                        ngx_upstream_check_peer_shm_t *opsh, ngx_uint_t init_down,
                                        ngx_pool_t *pool, ngx_str_t *name, ngx_str_t *upstream_name)
{
    u_char  *file;

    if (opsh) {
        psh->access_time  = opsh->access_time;
        psh->access_count = opsh->access_count;

        psh->fall_count   = opsh->fall_count;
        psh->rise_count   = opsh->rise_count;
        psh->busyness     = opsh->busyness;

        psh->down         = opsh->down;

    } else {
        psh->access_time  = 0;
        psh->access_count = 0;

        psh->fall_count   = 0;
        psh->rise_count   = 0;
        psh->busyness     = 0;

        psh->down         = init_down;
    }
    
    psh->upstream_name = upstream_name;

#if (NGX_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    file = ngx_pnalloc(pool, ngx_cycle->lock_file.len + name->len);
    if (file == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_sprintf(file, "%V%V%Z", &ngx_cycle->lock_file, name);

#endif

#if (nginx_version >= 1002000)
    if (ngx_shmtx_create(&psh->mutex, &psh->lock, file) != NGX_OK) {
#else
    if (ngx_shmtx_create(&psh->mutex, (void *) &psh->lock, file) != NGX_OK) {
#endif
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_check_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_upstream_check_main_conf_t  *ucmcf;
    ucmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_upstream_check_module);
    if (ucmcf == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                     "[ngx-healthcheck][stream][init-process] no stream section, skip init,stream_peers_ctx:%p",stream_peers_ctx);
        stream_peers_ctx = NULL;
        return NGX_OK;
    }

    return ngx_stream_upstream_check_add_timers(cycle);
}

