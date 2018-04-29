/*
 * Copyright (C) 2017- Changxun Zhou(zhoucx@dtdream.com)
 * desc: Healthcheck status interface
 */


#include <nginx.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_http.h>

#include "ngx_stream_upstream_check_module.h"

/* in different c source file, type declare can duplicate. :) */

typedef struct ngx_stream_upstream_check_peer_s ngx_stream_upstream_check_peer_t;
typedef struct ngx_stream_upstream_check_srv_conf_s ngx_stream_upstream_check_srv_conf_t;


typedef struct {
    ngx_shmtx_t                              mutex;
#if (nginx_version >= 1002000)
    ngx_shmtx_sh_t                           lock;
#else
    ngx_atomic_t                             lock;
#endif

    ngx_pid_t                                owner;

    ngx_msec_t                               access_time;

    ngx_uint_t                               fall_count;
    ngx_uint_t                               rise_count;

    ngx_uint_t                               busyness;
    ngx_uint_t                               access_count;

    struct sockaddr                         *sockaddr;
    socklen_t                                socklen;

    ngx_atomic_t                             down;          //current status.
    ngx_str_t                               *upstream_name;
    u_char                                   padding[64];
} ngx_stream_upstream_check_peer_shm_t;


typedef struct {
    ngx_uint_t                               generation; // current process generation(==reload_num +1)
    ngx_uint_t                               checksum;   // we can know if peer config file changed by calculate it.
    ngx_uint_t                               number;     // peers total num

    ngx_stream_upstream_check_peer_shm_t       peers[1]; // peers status data array.
} ngx_stream_upstream_check_peers_shm_t;



typedef ngx_int_t (*ngx_stream_upstream_check_packet_init_pt)
        (ngx_stream_upstream_check_peer_t *peer);
typedef ngx_int_t (*ngx_stream_upstream_check_packet_parse_pt)
        (ngx_stream_upstream_check_peer_t *peer);
typedef void (*ngx_stream_upstream_check_packet_clean_pt)
        (ngx_stream_upstream_check_peer_t *peer);

struct ngx_stream_upstream_check_peer_s {
    ngx_flag_t                               state;
    ngx_pool_t                              *pool;
    ngx_uint_t                               index;
    ngx_uint_t                               max_busy;
    ngx_str_t                               *upstream_name;
    ngx_addr_t                              *check_peer_addr;
    ngx_addr_t                              *peer_addr;
    ngx_event_t                              check_ev;
    ngx_event_t                              check_timeout_ev;
    ngx_peer_connection_t                    pc;

    void                                    *check_data;
    ngx_event_handler_pt                     send_handler;
    ngx_event_handler_pt                     recv_handler;

    ngx_stream_upstream_check_packet_init_pt   init; //zhoucx: function ptr
    ngx_stream_upstream_check_packet_parse_pt  parse;
    ngx_stream_upstream_check_packet_clean_pt  reinit;

    ngx_stream_upstream_check_peer_shm_t      *shm;
    ngx_stream_upstream_check_srv_conf_t      *conf;
};


typedef struct {
    ngx_str_t                                check_shm_name;
    ngx_uint_t                               checksum;
    ngx_array_t                              peers;

    ngx_stream_upstream_check_peers_shm_t     *peers_shm;
} ngx_stream_upstream_check_peers_t;


typedef struct {
    ngx_uint_t                               type;

    ngx_str_t                                name;

    ngx_str_t                                default_send;

    /* HTTP */
    ngx_uint_t                               default_status_alive;

    ngx_event_handler_pt                     send_handler;
    ngx_event_handler_pt                     recv_handler;

    ngx_stream_upstream_check_packet_init_pt   init;
    ngx_stream_upstream_check_packet_parse_pt  parse;
    ngx_stream_upstream_check_packet_clean_pt  reinit;

    unsigned need_pool;
    unsigned need_keepalive;
} ngx_check_conf_t;


typedef void (*ngx_stream_upstream_check_status_format_pt) (ngx_buf_t *b,
                                                            ngx_stream_upstream_check_peers_t *peers, ngx_uint_t flag);

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
    ngx_stream_upstream_check_peers_t         *peers;
} ngx_stream_upstream_check_main_conf_t;


struct ngx_stream_upstream_check_srv_conf_s {
    ngx_uint_t                               port;
    ngx_uint_t                               fall_count;
    ngx_uint_t                               rise_count;
    ngx_msec_t                               check_interval;
    ngx_msec_t                               check_timeout;
    ngx_uint_t                               check_keepalive_requests;

    ngx_check_conf_t                        *check_type_conf;
    ngx_str_t                                send;

    union {
        ngx_uint_t                           return_code;
        ngx_uint_t                           status_alive;
    } code;

    ngx_uint_t                               default_down;
};


typedef struct {
    ngx_check_status_conf_t                 *format;
} ngx_stream_upstream_check_loc_conf_t;


// external var declare
  extern ngx_uint_t ngx_stream_upstream_check_shm_generation ; //reload counter
  extern ngx_stream_upstream_check_peers_t *stream_peers_ctx ;  //stream peers data
  extern ngx_stream_upstream_check_peers_t *http_peers_ctx ; // http peers data


//begin check_status function declare
static ngx_int_t ngx_stream_upstream_check_status_handler(
    ngx_http_request_t *r); 
static void ngx_stream_upstream_check_status_parse_args(ngx_http_request_t *r,
    ngx_stream_upstream_check_status_ctx_t *ctx);

static ngx_int_t ngx_stream_upstream_check_status_command_format(
    ngx_stream_upstream_check_status_ctx_t *ctx, ngx_str_t *value);
static ngx_int_t ngx_stream_upstream_check_status_command_status(
    ngx_stream_upstream_check_status_ctx_t *ctx, ngx_str_t *value);

static void ngx_stream_upstream_check_status_html_format(ngx_buf_t *b,
    ngx_stream_upstream_check_peers_t *peers, ngx_uint_t flag);
static void ngx_stream_upstream_check_status_csv_format(ngx_buf_t *b,
    ngx_stream_upstream_check_peers_t *peers, ngx_uint_t flag);
static void ngx_stream_upstream_check_status_json_format(ngx_buf_t *b,
    ngx_stream_upstream_check_peers_t *peers, ngx_uint_t flag);
static ngx_check_status_conf_t *ngx_http_get_check_status_format_conf(
    ngx_str_t *str);

static char *ngx_stream_upstream_check_status(ngx_conf_t *cf, 
    ngx_command_t *cmd, void *conf);
static void *ngx_stream_upstream_check_create_loc_conf(ngx_conf_t *cf);
static char * ngx_stream_upstream_check_merge_loc_conf(ngx_conf_t *cf, 
    void *parent, void *child);
//end check_status function declare

//1 cmd define
static ngx_command_t  ngx_stream_upstream_check_status_commands[] = {
    { ngx_string("healthcheck_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1|NGX_CONF_NOARGS,
      ngx_stream_upstream_check_status,
      0,
      0,
      NULL },

      ngx_null_command
};
//2 ctx define
static ngx_http_module_t  ngx_stream_upstream_check_status_module_ctx = {
        NULL,                                    /* preconfiguration */
        NULL,                                    /* postconfiguration */

        NULL,                                    /* create main configuration */
        NULL,                                    /* init main configuration */

        NULL,                                    /* create server configuration */
        NULL,                                    /* merge server configuration */

        ngx_stream_upstream_check_create_loc_conf, /* create location configuration */
        ngx_stream_upstream_check_merge_loc_conf   /* merge location configuration */
};
//3 module define
ngx_module_t  ngx_stream_upstream_check_status_module = {
        NGX_MODULE_V1,
        &ngx_stream_upstream_check_status_module_ctx,   /* module context */
        ngx_stream_upstream_check_status_commands,      /* module directives */
        NGX_HTTP_MODULE,                       /* module type */
        NULL,                                  /* init master */
        NULL,                                  /* init module */
        NULL,                                  /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};
//health checker cmd callback.
static char *
ngx_stream_upstream_check_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value;
    ngx_http_core_loc_conf_t            *clcf;
    ngx_stream_upstream_check_loc_conf_t  *uclcf;

    value = cf->args->elts;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_stream_upstream_check_status_handler;

    if (cf->args->nelts == 2) {
        uclcf = ngx_http_conf_get_module_loc_conf(cf,
                                              ngx_stream_upstream_check_status_module);

        uclcf->format = ngx_http_get_check_status_format_conf(&value[1]);
        if (uclcf->format == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid check format \"%V\"", &value[1]);

            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
// location config  callback
static void *
ngx_stream_upstream_check_create_loc_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_check_loc_conf_t  *uclcf;

    uclcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_check_loc_conf_t));
    if (uclcf == NULL) {
        return NULL;
    }

    uclcf->format = NGX_CONF_UNSET_PTR;

    return uclcf;
}

static char *
ngx_stream_upstream_check_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_str_t                            format = ngx_string("html");
    ngx_stream_upstream_check_loc_conf_t  *prev = parent;
    ngx_stream_upstream_check_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->format, prev->format,
                             ngx_http_get_check_status_format_conf(&format));

    return NGX_CONF_OK;
}
// internal function define
static ngx_check_status_conf_t  ngx_check_status_formats[] = {

    { ngx_string("html"),
      ngx_string("text/html"),
      ngx_stream_upstream_check_status_html_format },

    { ngx_string("csv"),
      ngx_string("text/plain"),
      ngx_stream_upstream_check_status_csv_format },

    { ngx_string("json"),
      ngx_string("application/json"), // RFC 4627
      ngx_stream_upstream_check_status_json_format },

    { ngx_null_string, ngx_null_string, NULL }
};

static ngx_check_status_command_t ngx_check_status_commands[] =  {

    { ngx_string("format"),
      ngx_stream_upstream_check_status_command_format },

    { ngx_string("status"),
      ngx_stream_upstream_check_status_command_status },

    { ngx_null_string, NULL }
};

/* http request hander. */
static ngx_int_t
ngx_stream_upstream_check_status_handler(ngx_http_request_t *r)
{
    size_t                                 buffer_size;
    ngx_int_t                              rc;
    ngx_buf_t                             *b;
    ngx_chain_t                            out;
    ngx_stream_upstream_check_peers_t       *peers;
    ngx_stream_upstream_check_loc_conf_t    *uclcf;
    ngx_stream_upstream_check_status_ctx_t  *ctx;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                 "[ngx-healthcheck][status-interface] recv query request");

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    uclcf = ngx_http_get_module_loc_conf(r, ngx_stream_upstream_check_status_module);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_stream_upstream_check_status_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_stream_upstream_check_status_parse_args(r, ctx);

    if (ctx->format == NULL) {
        ctx->format = uclcf->format;
    }

    r->headers_out.content_type = ctx->format->content_type;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                 "[ngx-healthcheck][status-interface]"
                 " stream_peers_ctx:%p, http_peers_ctx:%p",
                 stream_peers_ctx, http_peers_ctx);

    peers = stream_peers_ctx; // status data provided by stream_upstream_health_check_module.
    if (peers == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[ngx-healthcheck][status-interface] peers == NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 1/4 pagesize for each record
    buffer_size = peers->peers.nelts * ngx_pagesize / 4;
    buffer_size = ngx_align(buffer_size, ngx_pagesize) + ngx_pagesize;

    b = ngx_create_temp_buf(r->pool, buffer_size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ctx->format->output(b, peers, ctx->flag); // construct status data.

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length_n == 0) {
        r->header_only = 1;
    }

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static void
ngx_stream_upstream_check_status_parse_args(ngx_http_request_t *r,
    ngx_stream_upstream_check_status_ctx_t *ctx)
{
    ngx_str_t                    value;
    ngx_uint_t                   i;
    ngx_check_status_command_t  *command;

    if (r->args.len == 0) {
        return;
    }

    for (i = 0;  ; i++) {

        command = &ngx_check_status_commands[i];

        if (command->name.len == 0) {
            break;
        }

        if (ngx_http_arg(r, command->name.data, command->name.len, &value)
            == NGX_OK) {

           if (command->handler(ctx, &value) != NGX_OK) {
               ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                             "stream upstream check, bad argument: \"%V\"",
                             &value);
           }
        }
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "stream upstream check, flag: \"%ui\"", ctx->flag);
}


static ngx_int_t
ngx_stream_upstream_check_status_command_format(
    ngx_stream_upstream_check_status_ctx_t *ctx, ngx_str_t *value)
{
    ctx->format = ngx_http_get_check_status_format_conf(value);
    if (ctx->format == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_check_status_command_status(
    ngx_stream_upstream_check_status_ctx_t *ctx, ngx_str_t *value)
{
    if (value->len == (sizeof("down") - 1)
        && ngx_strncasecmp(value->data, (u_char *) "down", value->len) == 0) {

        ctx->flag |= NGX_CHECK_STATUS_DOWN;

    } else if (value->len == (sizeof("up") - 1)
               && ngx_strncasecmp(value->data, (u_char *) "up", value->len)
               == 0) {

        ctx->flag |= NGX_CHECK_STATUS_UP;

    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_stream_upstream_check_status_html_format(ngx_buf_t *b,
    ngx_stream_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                      i, count;
    ngx_stream_upstream_check_peer_t *peer;

    peer = peers->peers.elts;

    count = 0;

    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        count++;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"
            "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
            "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
            "<head>\n"
            "  <title>Nginx stream upstream check status</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Nginx stream upstream check status</h1>\n"
            "<h2>Check upstream server number: %ui, generation: %ui</h2>\n"
            "<table style=\"background-color:white\" cellspacing=\"0\" "
            "       cellpadding=\"3\" border=\"1\">\n"
            "  <tr bgcolor=\"#C0C0C0\">\n"
            "    <th>Index</th>\n"
            "    <th>Upstream</th>\n"
            "    <th>Name</th>\n"
            "    <th>Status</th>\n"
            "    <th>Rise counts</th>\n"
            "    <th>Fall counts</th>\n"
            "    <th>Check type</th>\n"
            "    <th>Check port</th>\n"
            "  </tr>\n",
            count, ngx_stream_upstream_check_shm_generation);

    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "  <tr%s>\n"
                "    <td>%ui</td>\n"
                "    <td>%V</td>\n"
                "    <td>%V</td>\n"
                "    <td>%s</td>\n"
                "    <td>%ui</td>\n"
                "    <td>%ui</td>\n"
                "    <td>%V</td>\n"
                "    <td>%ui</td>\n"
                "  </tr>\n",
                peer[i].shm->down ? " bgcolor=\"#FF0000\"" : "",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->down ? "down" : "up",
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port);
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "</table>\n"
            "</body>\n"
            "</html>\n");
}


static void
ngx_stream_upstream_check_status_csv_format(ngx_buf_t *b,
    ngx_stream_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                       i;
    ngx_stream_upstream_check_peer_t  *peer;

    peer = peers->peers.elts;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "%ui,%V,%V,%s,%ui,%ui,%V,%ui\n",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->down ? "down" : "up",
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port);
    }
}


static void
ngx_stream_upstream_check_status_json_format(ngx_buf_t *b,
    ngx_stream_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                       count, i, last;
    ngx_stream_upstream_check_peer_t  *peer;


    /* calc display total num after filter param*/
    count = 0;

    peers = stream_peers_ctx; //stream
    peer = peers->peers.elts; 
    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        count++;
    }

    peers = http_peers_ctx; //http
    peer = peers->peers.elts; 
    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        count++;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "{\"servers\": {\n"
            "  \"total\": %ui,\n"
            "  \"generation\": %ui,\n"
            "  \"http\": [\n",
            count,
            ngx_stream_upstream_check_shm_generation);

//http
    last = peers->peers.nelts - 1;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "    {\"index\": %ui, "
                "\"upstream\": \"%V\", "
                "\"name\": \"%V\", "
                "\"status\": \"%s\", "
                "\"rise\": %ui, "
                "\"fall\": %ui, "
                "\"type\": \"%V\", "
                "\"port\": %ui}"
                "%s\n",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->down ? "down" : "up",
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port,
                (i == last) ? "" : ",");
    }

//http end

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "  ],\n"
            "  \"stream\": [\n");

    peers = stream_peers_ctx; //stream
    peer = peers->peers.elts; 

    last = peers->peers.nelts - 1;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "    {\"index\": %ui, "
                "\"upstream\": \"%V\", "
                "\"name\": \"%V\", "
                "\"status\": \"%s\", "
                "\"rise\": %ui, "
                "\"fall\": %ui, "
                "\"type\": \"%V\", "
                "\"port\": %ui}"
                "%s\n",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->down ? "down" : "up",
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port,
                (i == last) ? "" : ",");
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "  ]\n");

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "}}\n");
}

static ngx_check_status_conf_t *
ngx_http_get_check_status_format_conf(ngx_str_t *str)
{
    ngx_uint_t  i;

    for (i = 0;  ; i++) {

        if (ngx_check_status_formats[i].format.len == 0) {
            break;
        }

        if (str->len != ngx_check_status_formats[i].format.len) {
            continue;
        }

        if (ngx_strncmp(str->data, ngx_check_status_formats[i].format.data,
                        str->len) == 0)
        {
            return &ngx_check_status_formats[i];
        }
    }

    return NULL;
}


//end healthcheck status interface
