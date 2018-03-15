#ifndef _NGX_STREAM_UPSTREAM_CHECK_MODELE_H_INCLUDED_
#define _NGX_STREAM_UPSTREAM_CHECK_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

//add a backend server to health checker system.
ngx_uint_t ngx_stream_upstream_check_add_peer(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us, ngx_addr_t *peer);

//get status of one backend . 
ngx_uint_t ngx_stream_upstream_check_peer_down(ngx_uint_t index);

//inc peer's busyness cnt
void ngx_stream_upstream_check_get_peer(ngx_uint_t index); 

//dec peer's busyness cnt
void ngx_stream_upstream_check_free_peer(ngx_uint_t index);


#endif //_NGX_STREAM_UPSTREAM_CHECK_MODELE_H_INCLUDED_
