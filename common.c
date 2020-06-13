#include "common.h.in"

#define NGX_CHECK_HTTP_2XX                   0x0002
#define NGX_CHECK_HTTP_3XX                   0x0004
#define NGX_CHECK_HTTP_4XX                   0x0008
#define NGX_CHECK_HTTP_5XX                   0x0010
#define NGX_CHECK_HTTP_ERR                   0x8000

static ngx_int_t
ngx_upstream_check_parse_http_status_line(ngx_buf_t *b, ngx_uint_t *pstate, ngx_http_status_t *status)
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
        sw_lf,
        sw_cr,
        sw_almost_done
    } state;

    state = *pstate;
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
                        state = sw_lf;
                        break;
                    case LF:
                        goto done;
                }
                break;
            /* LF */
            case sw_lf:
                switch (ch) {
                case LF:
                    state = sw_cr;
                    break;
                default:
                    return NGX_ERROR;
                }
                break;
    
            /* CR */
            case sw_cr:
                switch (ch) {
                case CR:
                    state = sw_almost_done;
                    break;
                default:
                    state = sw_status_text;
                    break;
                }
                break;
    
            /* LF */
            case sw_almost_done:
                switch (ch) {
                case LF:
                    status->end = p - 1;
                    goto done;
                default:
                    return NGX_ERROR;
                }
        }
    }

    b->pos = p;
    *pstate = state;
    return NGX_AGAIN;

    done:
    // set pos to start of body.
    b->pos = p + 1;

    if (status->end == NULL) {
        status->end = p;
    }

    *pstate = sw_start;

    return NGX_OK;
}

ngx_int_t
ngx_upstream_check_http_parse(ngx_upstream_check_peer_t *peer)
{
    ngx_int_t                            rc;
    ngx_uint_t                           code, code_n;
    ngx_upstream_check_ctx_t       *ctx;
    ngx_upstream_check_srv_conf_t  *ucscf;

    ucscf = peer->conf;
    ctx = peer->check_data;

    if ((ctx->recv.last - ctx->recv.pos) > 0) {

        rc = ngx_upstream_check_parse_http_status_line(&ctx->recv,
                                                       &ctx->state,
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

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "http_parse: code_n: %ui, conf: %ui",
                       code_n, ucscf->code.status_alive);

        if (!(code_n & ucscf->code.status_alive)) {
            return NGX_ERROR;
        } else if (!(ucscf->body.len != 0 &&
            ngx_strstr(ctx->recv.pos, ucscf->body.data) == NULL)) {
            return NGX_ERROR;
        } else {
            return NGX_OK;
        }
    } else {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


