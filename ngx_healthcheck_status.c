/*
 * Copyright (C) 2017- Changxun Zhou(changxunzhou@qq.com)
 * desc: Healthcheck status interface
 */


#include <nginx.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_http.h>

#include "common.h.in"


#define NGX_CHECK_STATUS_DOWN                0x0001
#define NGX_CHECK_STATUS_UP                  0x0002

typedef void (*ngx_upstream_check_status_format_pt) (ngx_buf_t *b,
                                                     ngx_upstream_check_peers_t *peers,
                                                     ngx_uint_t flag);
typedef struct {
    ngx_str_t                                format;
    ngx_str_t                                content_type;

    ngx_upstream_check_status_format_pt output;
} ngx_check_status_conf_t;

typedef struct {
    ngx_check_status_conf_t                 *format;
    ngx_flag_t                               flag;
} ngx_upstream_check_status_ctx_t;


typedef ngx_int_t (*ngx_upstream_check_status_command_pt)
        (ngx_upstream_check_status_ctx_t *ctx, ngx_str_t *value);

typedef struct {
    ngx_str_t                                 name;
    ngx_upstream_check_status_command_pt      handler;
} ngx_check_status_command_t;

// check module main config data.
typedef struct {
    ngx_uint_t                          check_shm_size;
    ngx_upstream_check_peers_t         *peers;
} ngx_upstream_check_main_conf_t;


typedef struct {
    ngx_check_status_conf_t                 *format;
} ngx_upstream_check_loc_conf_t;


// external var declare
  extern ngx_uint_t ngx_stream_upstream_check_shm_generation ; //reload counter
  extern ngx_upstream_check_peers_t *stream_peers_ctx ;  //stream peers data
  extern ngx_upstream_check_peers_t *http_peers_ctx ; // http peers data


//begin check_status function declare
static ngx_int_t ngx_upstream_check_status_handler(
    ngx_http_request_t *r); 
static void ngx_upstream_check_status_parse_args(ngx_http_request_t *r,
    ngx_upstream_check_status_ctx_t *ctx);

static ngx_int_t ngx_upstream_check_status_command_format(
    ngx_upstream_check_status_ctx_t *ctx, ngx_str_t *value);
static ngx_int_t ngx_upstream_check_status_command_status(
    ngx_upstream_check_status_ctx_t *ctx, ngx_str_t *value);

static void ngx_upstream_check_status_html_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag);
static void ngx_upstream_check_status_csv_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag);
static void ngx_upstream_check_status_json_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag);
static void ngx_http_upstream_check_status_prometheus_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag);

static ngx_check_status_conf_t *ngx_http_get_check_status_format_conf(
    ngx_str_t *str);

static char *ngx_upstream_check_status(ngx_conf_t *cf, 
    ngx_command_t *cmd, void *conf);
static void *ngx_upstream_check_create_loc_conf(ngx_conf_t *cf);
static char * ngx_upstream_check_merge_loc_conf(ngx_conf_t *cf, 
    void *parent, void *child);
//end check_status function declare

//1 cmd define
static ngx_command_t  ngx_upstream_check_status_commands[] = {
    { ngx_string("healthcheck_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1|NGX_CONF_NOARGS,
      ngx_upstream_check_status,
      0,
      0,
      NULL },

      ngx_null_command
};
//2 ctx define
static ngx_http_module_t  ngx_upstream_check_status_module_ctx = {
        NULL,                                    /* preconfiguration */
        NULL,                                    /* postconfiguration */

        NULL,                                    /* create main configuration */
        NULL,                                    /* init main configuration */

        NULL,                                    /* create server configuration */
        NULL,                                    /* merge server configuration */

        ngx_upstream_check_create_loc_conf, /* create location configuration */
        ngx_upstream_check_merge_loc_conf   /* merge location configuration */
};
//3 module define
ngx_module_t  ngx_upstream_check_status_module = {
        NGX_MODULE_V1,
        &ngx_upstream_check_status_module_ctx,   /* module context */
        ngx_upstream_check_status_commands,      /* module directives */
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
ngx_upstream_check_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value;
    ngx_http_core_loc_conf_t            *clcf;
    ngx_upstream_check_loc_conf_t  *uclcf;

    value = cf->args->elts;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_upstream_check_status_handler;

    if (cf->args->nelts == 2) {
        uclcf = ngx_http_conf_get_module_loc_conf(cf,
                                              ngx_upstream_check_status_module);

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
ngx_upstream_check_create_loc_conf(ngx_conf_t *cf)
{
    ngx_upstream_check_loc_conf_t  *uclcf;

    uclcf = ngx_pcalloc(cf->pool, sizeof(ngx_upstream_check_loc_conf_t));
    if (uclcf == NULL) {
        return NULL;
    }

    uclcf->format = NGX_CONF_UNSET_PTR;

    return uclcf;
}

static char *
ngx_upstream_check_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_str_t                            format = ngx_string("html");
    ngx_upstream_check_loc_conf_t  *prev = parent;
    ngx_upstream_check_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->format, prev->format,
                             ngx_http_get_check_status_format_conf(&format));

    return NGX_CONF_OK;
}

static ngx_check_status_conf_t  ngx_check_status_formats[] = {

    { ngx_string("html"),
      ngx_string("text/html"),
      ngx_upstream_check_status_html_format },

    { ngx_string("csv"),
      ngx_string("text/plain"),
      ngx_upstream_check_status_csv_format },

    { ngx_string("json"),
      ngx_string("application/json"), // RFC 4627
      ngx_upstream_check_status_json_format },

    { ngx_string("prometheus"),
      ngx_string("text/plain"),
      ngx_http_upstream_check_status_prometheus_format },

    { ngx_null_string, ngx_null_string, NULL }
};

static ngx_check_status_command_t ngx_check_status_commands[] =  {

    { ngx_string("format"),
      ngx_upstream_check_status_command_format },

    { ngx_string("status"),
      ngx_upstream_check_status_command_status },

    { ngx_null_string, NULL }
};

/* http request handler. */
static ngx_int_t
ngx_upstream_check_status_handler(ngx_http_request_t *r)
{
    size_t                                 buffer_size;
    ngx_int_t                              rc;
    ngx_buf_t                             *b;
    ngx_chain_t                            out;
    ngx_upstream_check_peers_t       *peers;
    ngx_upstream_check_loc_conf_t    *uclcf;
    ngx_upstream_check_status_ctx_t  *ctx;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                 "[ngx-healthcheck][status-interface] recv query request");

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    uclcf = ngx_http_get_module_loc_conf(r, ngx_upstream_check_status_module);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_upstream_check_status_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_upstream_check_status_parse_args(r, ctx);

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
    peers = http_peers_ctx; 
/*
    if (peers == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "[ngx-healthcheck][status-interface] peers == NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
*/
    // 1/4 pagesize for each record
    if(stream_peers_ctx == NULL){
        buffer_size = http_peers_ctx->peers.nelts * ngx_pagesize / 4;
    }else{
        buffer_size = (stream_peers_ctx->peers.nelts + http_peers_ctx->peers.nelts) * ngx_pagesize / 4;
    }
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
ngx_upstream_check_status_parse_args(ngx_http_request_t *r,
    ngx_upstream_check_status_ctx_t *ctx)
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
ngx_upstream_check_status_command_format(
    ngx_upstream_check_status_ctx_t *ctx, ngx_str_t *value)
{
    ctx->format = ngx_http_get_check_status_format_conf(value);
    if (ctx->format == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_upstream_check_status_command_status(
    ngx_upstream_check_status_ctx_t *ctx, ngx_str_t *value)
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
ngx_upstream_check_status_html_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t i,stream_count,http_count,stream_up_count,http_up_count;
    ngx_upstream_check_peer_t *peer;

    stream_count = 0;
    http_count = 0;
    stream_up_count = 0;
    http_up_count = 0;

    peers = stream_peers_ctx;
    if(peers != NULL){
        peer = peers->peers.elts;
        for (i = 0; i < peers->peers.nelts; i++) {
            if (!peer[i].shm->down) {
                   stream_up_count ++;
            }
            stream_count++;
        }
    }

    peers = http_peers_ctx; //http
    peer = peers->peers.elts; 
    for (i = 0; i < peers->peers.nelts; i++) {
        if (!peer[i].shm->down) {
               http_up_count ++;
        }
        http_count++;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"
            "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
            "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
            "<head>\n"
            "  <title>Nginx upstream status checker</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1  align=\"center\">Nginx upstream status monitor</h1>\n");

// =======begin http data==========
    b->last = ngx_snprintf(b->last, b->end - b->last,
            "<h2>http upstream servers </h2> up: %ui down: %ui total: %ui\n"
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
            http_up_count, http_count-http_up_count, http_count);

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
            "</table>\n");

// =======begin stream data==========

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "<h2>stream upstream servers </h2> up: %ui down: %ui total: %ui\n"
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
            stream_up_count, stream_count-stream_up_count, stream_count);

    peers = stream_peers_ctx; //stream
    if(peers != NULL){
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
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "</table>\n"
            "<h2>total servers(check enabled): %ui </h2>\n"
            "</body></html>\n",
            stream_count+http_count);
}


static void
ngx_upstream_check_status_csv_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                       i;
    ngx_upstream_check_peer_t  *peer;

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "index,upstream_type,upstream_name,host,rise,fall,check_type,check_port,status\n");
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

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "%ui,http,%V,%V,%ui,%ui,%V,%ui,%s\n",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port,
                peer[i].shm->down ? "down" : "up");
    }
    peers = stream_peers_ctx; //stream
    if(peers == NULL) return;
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
                "%ui,stream,%V,%V,%ui,%ui,%V,%ui,%s\n",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port,
                peer[i].shm->down ? "down" : "up");
    }
}


static void
ngx_upstream_check_status_json_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                 count, i;
    ngx_uint_t stream_count=0, http_count=0;
    ngx_upstream_check_peer_t  *peer;


    /* calc display total num after filter param*/
    count = 0;

    peers = stream_peers_ctx; //stream
    if(peers != NULL){  //when no stream section, peers is NULL
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
            count++;stream_count++;
        }
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
        count++;http_count++;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "{\"servers\": {\n"
            "  \"total\": %ui,\n"
            "  \"generation\": %ui,\n"
            "  \"http\": [\n",
            count,
            ngx_stream_upstream_check_shm_generation);

//http
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
                (count == http_count) ? "" : ",");
    }

//http end

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "  ],\n"
            "  \"stream\": [\n");

    peers = stream_peers_ctx; //stream
    count = 0;
    if(peers != NULL){
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
                    (count == stream_count) ? "" : ",");
        }
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "  ]\n");

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "}}\n");
}


static void
ngx_http_upstream_check_status_prometheus_format(ngx_buf_t *b,
    ngx_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                    count, upCount, downCount, i, j;
    ngx_upstream_check_peer_t    *peer;
    ngx_str_t                     upstream_type[2] = {ngx_string("http"), ngx_string("stream")};
    ngx_upstream_check_peers_t   *upstream_peers[2] = {http_peers_ctx, stream_peers_ctx};

    /* 1. summary */
    upCount = 0;
    downCount = 0;
    count = 0;
    for(j=0; j < 2; j++) {
        peers = upstream_peers[j];
        if (peers == NULL) continue;
        peer = peers->peers.elts;

        for (i = 0; i < peers->peers.nelts; i++) {
    /*
            if (peer[i].delete) {
                continue;
            }
    */
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
            if (peer[i].shm->down) {
                downCount++;
            } else {
                upCount++;
            }
        }
    }
    b->last = ngx_snprintf(b->last, b->end - b->last,
        "# HELP nginx_upstream_count_total Nginx total number of servers\n"
        "# TYPE nginx_upstream_count_total gauge\n"
        "nginx_upstream_count_total %ui\n"
        "# HELP nginx_upstream_count_up Nginx total number of servers that are UP\n"
        "# TYPE nginx_upstream_count_up gauge\n"
        "nginx_upstream_count_up %ui\n"
        "# HELP nginx_upstream_count_down Nginx total number of servers that are DOWN\n"
        "# TYPE nginx_upstream_count_down gauge\n"
        "nginx_upstream_count_down %ui\n"
        "# HELP nginx_upstream_count_generation Nginx generation\n"
        "# TYPE nginx_upstream_count_generation gauge\n"
        "nginx_upstream_count_generation %ui\n",
        count,
        upCount,
        downCount,
        ngx_stream_upstream_check_shm_generation);

    /* 2. ngninx_upstream_server_rise */
    b->last = ngx_snprintf(b->last, b->end - b->last,
            "# HELP nginx_upstream_server_rise Nginx rise counter\n"
            "# TYPE nginx_upstream_server_rise counter\n");

    for(j=0; j < 2; j++) {
        peers = upstream_peers[j];
        if (peers == NULL) continue;
        peer = peers->peers.elts;

        for (i = 0; i < peers->peers.nelts; i++) {
    /*
            if (peer[i].delete) {
                continue;
            }
    */
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
                    "nginx_upstream_server_rise{index=\"%ui\",upstream_type=\"%V\",upstream=\"%V\",name=\"%V\",status=\"%s\",type=\"%V\",port=\"%ui\"} %ui\n",
                    i,
                    &upstream_type[j],
                    peer[i].upstream_name,
                    &peer[i].peer_addr->name,
                    peer[i].shm->down ? "down" : "up",
                    &peer[i].conf->check_type_conf->name,
                    peer[i].conf->port,
                    peer[i].shm->rise_count);
        }
    }

    /* 3. ngninx_upstream_server_fall */
    b->last = ngx_snprintf(b->last, b->end - b->last,
            "# HELP nginx_upstream_server_fall Nginx fall counter\n"
            "# TYPE nginx_upstream_server_fall counter\n");
    for(j=0; j < 2; j++) {
        peers = upstream_peers[j];
        if (peers == NULL) continue;
        peer = peers->peers.elts;

        for (i = 0; i < peers->peers.nelts; i++) {
    /*
            if (peer[i].delete) {
                continue;
            }
    */
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
                    "nginx_upstream_server_fall{index=\"%ui\",upstream_type=\"%V\",upstream=\"%V\",name=\"%V\",status=\"%s\",type=\"%V\",port=\"%ui\"} %ui\n",
                    i,
                    &upstream_type[j],
                    peer[i].upstream_name,
                    &peer[i].peer_addr->name,
                    peer[i].shm->down ? "down" : "up",
                    &peer[i].conf->check_type_conf->name,
                    peer[i].conf->port,
                    peer[i].shm->fall_count);
        }
    }

    /* 4. ngninx_upstream_server_active */
    b->last = ngx_snprintf(b->last, b->end - b->last,
            "# HELP nginx_upstream_server_active Nginx active 1 for UP / 0 for DOWN\n"
            "# TYPE nginx_upstream_server_active gauge\n");
    for(j=0; j < 2; j++) {
        peers = upstream_peers[j];
        if (peers == NULL) continue;
        peer = peers->peers.elts;

        for (i = 0; i < peers->peers.nelts; i++) {
    /*
            if (peer[i].delete) {
                continue;
            }
    */
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
                    "nginx_upstream_server_active{index=\"%ui\",upstream_type=\"%V\",upstream=\"%V\",name=\"%V\",type=\"%V\",port=\"%ui\"} %ui\n",
                    i,
                    &upstream_type[j],
                    peer[i].upstream_name,
                    &peer[i].peer_addr->name,
                    &peer[i].conf->check_type_conf->name,
                    peer[i].conf->port,
                    peer[i].shm->down ? 0 : 1);
        }
    }
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
