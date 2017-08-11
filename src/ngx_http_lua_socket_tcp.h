
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_SOCKET_TCP_H_INCLUDED_
#define _NGX_HTTP_LUA_SOCKET_TCP_H_INCLUDED_


#include "ngx_http_lua_common.h"


#define NGX_HTTP_LUA_SOCKET_FT_ERROR         0x0001
#define NGX_HTTP_LUA_SOCKET_FT_TIMEOUT       0x0002
#define NGX_HTTP_LUA_SOCKET_FT_CLOSED        0x0004
#define NGX_HTTP_LUA_SOCKET_FT_RESOLVER      0x0008
#define NGX_HTTP_LUA_SOCKET_FT_BUFTOOSMALL   0x0010
#define NGX_HTTP_LUA_SOCKET_FT_NOMEM         0x0020
#define NGX_HTTP_LUA_SOCKET_FT_PARTIALWRITE  0x0040
#define NGX_HTTP_LUA_SOCKET_FT_CLIENTABORT   0x0080
#define NGX_HTTP_LUA_SOCKET_FT_SSL           0x0100


typedef struct ngx_http_lua_socket_tcp_upstream_s
        ngx_http_lua_socket_tcp_upstream_t;


typedef
    int (*ngx_http_lua_socket_tcp_retval_handler)(ngx_http_request_t *r,
        ngx_http_lua_socket_tcp_upstream_t *u, lua_State *L);


typedef void (*ngx_http_lua_socket_tcp_upstream_handler_pt)
    (ngx_http_request_t *r, ngx_http_lua_socket_tcp_upstream_t *u);


typedef struct {
    lua_State    *lua_vm;

    /* active connections == out-of-pool reused connections
     *                       + in-pool connections */
    ngx_uint_t   active_connections;

    /* queues of ngx_http_lua_socket_pool_item_t: */
    ngx_queue_t  cache;        /* 缓存的可用链路 */
    ngx_queue_t  free;         /* 已被使用的链路 */

    u_char       key[1];       /* */

} ngx_http_lua_socket_pool_t;

/* cosocket对应的上下文
   此对象的元表为 ngx_http_lua_upstream_udata_metatable_key 索引的全局注册表 */
struct ngx_http_lua_socket_tcp_upstream_s {
    ngx_http_lua_socket_tcp_retval_handler  read_prepare_retvals;
                              /* receive: ngx_http_lua_socket_tcp_receive_retval_handler() */
    ngx_http_lua_socket_tcp_retval_handler  write_prepare_retvals;
                              /* connect: ngx_http_lua_socket_tcp_conn_retval_handler()
                                 sslhandshake: ngx_http_lua_ssl_handshake_retval_handler() */
    ngx_http_lua_socket_tcp_upstream_handler_pt read_event_handler;
    ngx_http_lua_socket_tcp_upstream_handler_pt write_event_handler;

    ngx_http_lua_socket_pool_t *socket_pool;  /* 缓存的链路结构 */

    ngx_http_lua_loc_conf_t *conf; /* 对应的location配置 */
    ngx_http_cleanup_pt *cleanup;
    ngx_http_request_t  *request;  /* 对应的请求 */
    ngx_peer_connection_t peer;    /* 维护底层链路信息 */

    ngx_msec_t read_timeout;       /* 超时时限 */
    ngx_msec_t send_timeout;
    ngx_msec_t connect_timeout;

    ngx_http_upstream_resolved_t *resolved; /* 如果指定的HOST:PORT为域名，此处
                                               保存域名解析后的结果 */

    ngx_chain_t *bufs_in;   /* 接收数据链，input data buffers */
    ngx_chain_t *buf_in;    /* 当前操控的缓存，last input data buffer */
    ngx_buf_t buffer;       /* 当前操空的缓存buf，receive buffer */

    size_t    length;       /* 待读取数据总长度 */
    size_t    rest;         /* 尚未读取的数据长度 */

    ngx_err_t socket_errno;

    ngx_int_t (*input_filter)(void *data, ssize_t bytes);  /* 检查数据是否准备就绪 */
    void      *input_filter_ctx;     /* 未指定读字节数= ngx_http_lua_socket_read_line()
                                        指定读字节数= ngx_http_lua_socket_read_chunk()
                                        读类型为“a”= ngx_http_lua_socket_read_all() */
                                     /* 指向本结构自身 */

    size_t    request_len;     /* 待发送数据 */
    ngx_chain_t *request_bufs;

    ngx_http_lua_co_ctx_t *read_co_ctx;
    ngx_http_lua_co_ctx_t *write_co_ctx;

    ngx_uint_t reused;

#if (NGX_HTTP_SSL)
    ngx_str_t ssl_name;          /* 指定需要连接的服务器名，以应对单IP提供多SSL服务的情况 */
#endif

    unsigned ft_type:16;
    unsigned no_close:1;
    unsigned conn_waiting:1;     /* 等待链接建立成功 */
    unsigned read_waiting:1;     /* 等待读取数据 */
    unsigned write_waiting:1;    /* 等待写数据 */
    unsigned eof:1;
    unsigned body_downstream:1;
    unsigned raw_downstream:1;
    unsigned read_closed:1;
    unsigned write_closed:1;
#if (NGX_HTTP_SSL)
    unsigned ssl_verify:1;       /* 是否验证服务器端证书 */
    unsigned ssl_session_reuse:1;/* 是否开启会话恢复机制 */
#endif
};


typedef struct ngx_http_lua_dfa_edge_s  ngx_http_lua_dfa_edge_t;


struct ngx_http_lua_dfa_edge_s {
    u_char                           chr;
    int                              new_state;
    ngx_http_lua_dfa_edge_t         *next;
};


typedef struct {
    ngx_http_lua_socket_tcp_upstream_t  *upstream;

    ngx_str_t                            pattern;
    int                                  state;
    ngx_http_lua_dfa_edge_t            **recovering;

    unsigned                             inclusive:1;
} ngx_http_lua_socket_compiled_pattern_t;


typedef struct {
    ngx_http_lua_socket_pool_t      *socket_pool;

    ngx_queue_t                      queue;
    ngx_connection_t                *connection;

    socklen_t                        socklen;
    struct sockaddr_storage          sockaddr;

    ngx_uint_t                       reused;

} ngx_http_lua_socket_pool_item_t;


void ngx_http_lua_inject_socket_tcp_api(ngx_log_t *log, lua_State *L);
void ngx_http_lua_inject_req_socket_api(lua_State *L);
void ngx_http_lua_cleanup_conn_pools(lua_State *L);


#endif /* _NGX_HTTP_LUA_SOCKET_TCP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
