/*
 * Copyright (C) 2017- Changxun Zhou(changxunzhou@qq.com)
 * desc: nginx upstream server health check.
 * date: 2020-06-21 23:40
 */
#include "common.h.in"

ngx_int_t
ngx_upstream_check_http_body_regex(ngx_conf_t *cf, ngx_upstream_check_srv_conf_t  *ucscf,
    ngx_str_t *regex, ngx_uint_t caseless)
{
#if (NGX_PCRE)
    ngx_regex_compile_t  rc;
    u_char               errstr[NGX_MAX_CONF_ERRSTR];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *regex;

rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pool = cf->pool;

#if (NGX_HAVE_CASELESS_FILESYSTEM)
    rc.options = NGX_REGEX_CASELESS;
#else
    rc.options = caseless ? NGX_REGEX_CASELESS : 0;
#endif

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ngx_regex_compile: %V",
                            &rc.err);
        return NGX_ERROR;
    }

    ucscf->expect_body_regex = rc.regex;
    return NGX_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return NGX_ERROR;

#endif
}

#define NGX_PCRE 1

ngx_int_t
ngx_upstream_check_http_header_regex(ngx_conf_t *cf, ngx_upstream_check_header_conf_t *uchcf,
                                   ngx_str_t *regex, ngx_uint_t is_caseless)
{
#if (NGX_PCRE)
    ngx_regex_compile_t  rc;
    u_char               errstr[NGX_MAX_CONF_ERRSTR];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *regex;

rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pool = cf->pool;

#if (NGX_HAVE_CASELESS_FILESYSTEM)
    rc.options = NGX_REGEX_CASELESS;
#else
    rc.options = is_caseless ? 1 : 0;
#endif

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ngx_regex_compile: %V",
                            &rc.err);
        return NGX_ERROR;
    }

    uchcf->arg_regex = rc.regex;

    return NGX_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return NGX_ERROR;

#endif
}

ngx_int_t
ngx_upstream_check_http_parse_status_line(
    ngx_buf_t *b, ngx_uint_t *pstate, ngx_http_status_t *status,ngx_list_t *header)
{
    u_char ch, *p;
    ngx_table_elt_t *elt;
    size_t count;
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

        sw_header_cr,
        sw_header_lf,
        sw_header_end,
        //special
        receive_body,

        sw_status_line_end,

        sw_header_start_key,
        sw_header_key,

        sw_header_start_value,
        sw_header_value,
//        sw_lf,
//        sw_cr,
//        sw_almost_done,
//        receive_body
    } state;

    state = *pstate;

    if (state == receive_body) {
        return NGX_OK;
    }

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
                        state = sw_status_line_end;
                        break;
                    // why not return error
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
                        state = sw_status_line_end;
                        break;
                    // why not return error
                    case LF:
                        goto done;
                }
                break;

            /* LF */
            case sw_status_line_end:
                switch (ch) {
                case LF:
                    state = sw_header_start_key;
                    break;
                default:
                    return NGX_ERROR;
                }
                break;

            case sw_header_start_key:
                switch (ch) {
                    case CR: /* body but unsafe*/
                        state = sw_header_end;
                        break;

                    default: /* response header */
                        //add key
                        count = 1;
                        elt = ngx_list_push(header);

                        elt->key.data = p;
                        state = sw_header_key;
                        break;
                }
                break;

            case sw_header_key:
                switch (ch) {
                    case ':': /* second CR */
                        elt->key.len = count;
                        //ngx_log_error(NGX_LOG_ERR,ngx_cycle->log,0,"find key ->%V, len-> %z",&(elt->key),&(elt->key.len));
                        count = 1;
                        state = sw_header_start_value;
                        break;
                    default: /* response header */
                        //add key
                        count++;
                        break;
                }
                break;

            case sw_header_start_value:
                switch (ch) {
                    case ' ':
                        break;
                    case LF:
                        return NGX_ERROR;
                    case CR:
                        return NGX_ERROR;
                    // other
                    default:
                        count = 1;
                        elt->value.data = p;
                        state = sw_header_value;
                        //add value
                        break;
                }
                break;

            case sw_header_value:
                switch (ch) {
                    case CR:
                        elt->value.len = count;
                        //ngx_log_error(NGX_LOG_ERR,ngx_cycle->log,0,"find value ->%V,len -> %z",&(elt->value),&(elt->value.len));
                        count = 1;
                        state = sw_header_cr;
                        break;
                    default:
                        //add value
                        count++;
                        break;
                }
                break;

            case sw_header_cr:
                switch (ch) {
                    case LF:
                        state = sw_header_lf;
                        break;
                    default:
                        return NGX_ERROR;
                }
                break;

            case sw_header_lf:
                switch (ch) {
                    case CR:
                        state = sw_header_end;
                        break;
                    default:
                        //add key
                        elt = ngx_list_push(header);
                        count = 1;
                        elt->key.data = p;
                        state = sw_header_key;
                        break;
                }
                break;

                /* body */
            case sw_header_end:
                switch (ch) {
                    case LF:
                        /* all header_end */
                        status->end = p - 1;
                        goto done;
                    default:
                        return NGX_ERROR;
                }
            // how to use
            case receive_body:
                return NGX_OK;

/*            *//* CR *//*
            case sw_cr:
                switch (ch) {
                case CR: *//* second CR *//*
                    state = sw_almost_done;
                    break;
                default: *//* response header *//*
                    state = sw_status_text;
                    break;
                }
                break;

            *//* LF *//*
            case sw_almost_done:
                switch (ch) {
                case LF:
                    *//* all header_end *//*
                    status->end = p - 1;
                    goto done;
                default:
                    return NGX_ERROR;
                }
            case receive_body:
                return NGX_OK;*/
        }
    }

    // save parsed state.
    b->pos = p;
    *pstate = state;
    return NGX_AGAIN;

    done:
    // set pos to start of body.
    b->pos = p + 1;

    if (status->end == NULL) {
        status->end = p;
    }
    *pstate = receive_body;

    return NGX_OK;
}

