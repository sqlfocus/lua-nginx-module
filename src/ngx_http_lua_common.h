
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_LUA_COMMON_H_INCLUDED_
#define _NGX_HTTP_LUA_COMMON_H_INCLUDED_


#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include <setjmp.h>
#include <stdint.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#if !defined(nginx_version) || (nginx_version < 1006000)
#error at least nginx 1.6.0 is required but found an older version
#endif


#if defined(NDK) && NDK
#include <ndk.h>
#endif


#if LUA_VERSION_NUM != 501
#   error unsupported Lua language version
#endif


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)
#   define NGX_HTTP_LUA_USE_OCSP 1
#endif


#ifndef NGX_HAVE_SHA1
#   if (nginx_version >= 1011002)
#       define NGX_HAVE_SHA1  1
#   endif
#endif


#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif


#ifdef NGX_LUA_USE_ASSERT
#   include <assert.h>
#   define ngx_http_lua_assert(a)  assert(a)
#else
#   define ngx_http_lua_assert(a)
#endif


/* Nginx HTTP Lua Inline tag prefix */

#define NGX_HTTP_LUA_INLINE_TAG "nhli_"

#define NGX_HTTP_LUA_INLINE_TAG_LEN \
    (sizeof(NGX_HTTP_LUA_INLINE_TAG) - 1)

#define NGX_HTTP_LUA_INLINE_KEY_LEN \
    (NGX_HTTP_LUA_INLINE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

/* Nginx HTTP Lua File tag prefix */

#define NGX_HTTP_LUA_FILE_TAG "nhlf_"

#define NGX_HTTP_LUA_FILE_TAG_LEN \
    (sizeof(NGX_HTTP_LUA_FILE_TAG) - 1)

#define NGX_HTTP_LUA_FILE_KEY_LEN \
    (NGX_HTTP_LUA_FILE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)


#if defined(NDK) && NDK
typedef struct {
    size_t       size;
    u_char      *key;
    ngx_str_t    script;
} ngx_http_lua_set_var_data_t;
#endif


#ifndef NGX_HTTP_LUA_MAX_ARGS
#define NGX_HTTP_LUA_MAX_ARGS 100
#endif


#ifndef NGX_HTTP_LUA_MAX_HEADERS
#define NGX_HTTP_LUA_MAX_HEADERS 100
#endif


/* must be within 16 bit */
#define NGX_HTTP_LUA_CONTEXT_SET            0x0001
#define NGX_HTTP_LUA_CONTEXT_REWRITE        0x0002
#define NGX_HTTP_LUA_CONTEXT_ACCESS         0x0004
#define NGX_HTTP_LUA_CONTEXT_CONTENT        0x0008
#define NGX_HTTP_LUA_CONTEXT_LOG            0x0010
#define NGX_HTTP_LUA_CONTEXT_HEADER_FILTER  0x0020
#define NGX_HTTP_LUA_CONTEXT_BODY_FILTER    0x0040
#define NGX_HTTP_LUA_CONTEXT_TIMER          0x0080
#define NGX_HTTP_LUA_CONTEXT_INIT_WORKER    0x0100
#define NGX_HTTP_LUA_CONTEXT_BALANCER       0x0200
#define NGX_HTTP_LUA_CONTEXT_SSL_CERT       0x0400
#define NGX_HTTP_LUA_CONTEXT_SSL_SESS_STORE 0x0800
#define NGX_HTTP_LUA_CONTEXT_SSL_SESS_FETCH 0x1000


#ifndef NGX_LUA_NO_FFI_API
#define NGX_HTTP_LUA_FFI_NO_REQ_CTX         -100
#define NGX_HTTP_LUA_FFI_BAD_CONTEXT        -101
#endif


typedef struct ngx_http_lua_main_conf_s  ngx_http_lua_main_conf_t;
typedef union ngx_http_lua_srv_conf_u  ngx_http_lua_srv_conf_t;


typedef struct ngx_http_lua_balancer_peer_data_s
    ngx_http_lua_balancer_peer_data_t;


typedef struct ngx_http_lua_sema_mm_s  ngx_http_lua_sema_mm_t;


typedef ngx_int_t (*ngx_http_lua_main_conf_handler_pt)(ngx_log_t *log,
    ngx_http_lua_main_conf_t *lmcf, lua_State *L);
typedef ngx_int_t (*ngx_http_lua_srv_conf_handler_pt)(ngx_http_request_t *r,
    ngx_http_lua_srv_conf_t *lmcf, lua_State *L);


typedef struct {
    u_char              *package;
    lua_CFunction        loader;
} ngx_http_lua_preload_hook_t;

/* lua nginx模块儿主环境配置，即http{}层级配置 */
struct ngx_http_lua_main_conf_s {
    lua_State *lua;        /* lua引擎栈 */

    ngx_str_t  lua_path;   /* 对应配置指令“Lua_package_path”，lua脚本搜索路径 */
    ngx_str_t  lua_cpath;  /* 对应配置指令“Lua_package_cpath”，lua c模块儿搜索路径 */

    ngx_cycle_t *cycle;
    ngx_pool_t  *pool;

    ngx_int_t  max_pending_timers;  /* 最大的悬挂定时器数，“lua_max_pending_timers 1024” */
    ngx_int_t  pending_timers;      /* Pending timers are those timers that have not expired yet*/

    ngx_int_t  max_running_timers;  /* 允许的最大并行定时器数量，"lua_max_running_timers 256" */
    ngx_int_t  running_timers;      /* Running timers are those timers whose user callback functions are still running */

    ngx_connection_t    *watcher;   /* for watching the process exit event */

#if (NGX_PCRE)
    ngx_int_t            regex_cache_entries;
    ngx_int_t            regex_cache_max_entries;
    ngx_int_t            regex_match_limit;
#endif

#if 0
struct ngx_shm_zone_s {
    void  *data;        /* 对应的模块儿信息，如 ngx_http_lua_shdict_ctx_t */
    ngx_shm_t shm;      /* 详细描述信息 */
    ngx_shm_zone_init_pt init; /* 初始回调函数，如 ngx_http_lua_shdict_init_zone() */
    void *tag;          /* 标签，一般为模块儿地址信息，区分共享内存的用途；
                              防止不同模块儿创建同名称的共享内存，造成逻辑混乱
                              ngx_http_lua_module */
    ngx_uint_t noreuse; /* unsigned  noreuse:1; 是否可重用? 可重用的情况
                              下，在reload处理时，没有变化的共享内存不必再重
                              新分配，仅仅重新初始化就ok */
};
#endif
    ngx_array_t *shm_zones;/* 通过配置指令lua_shared_dict申请的
                              共享内存描述结构指针数组, ngx_shm_zone_t* */

    ngx_array_t *preload_hooks; /* of ngx_http_lua_preload_hook_t */

    ngx_flag_t  postponed_to_rewrite_phase_end;  /* Lua脚本是否在本阶段最后执行 */
    ngx_flag_t  postponed_to_access_phase_end;

    ngx_http_lua_main_conf_handler_pt    init_handler;
    ngx_str_t init_src;       /* 对应配置指令“init_by_lua_file”, ngx_http_lua_init_by_file() */

    ngx_http_lua_main_conf_handler_pt init_worker_handler;
    ngx_str_t init_worker_src;/* 对应配置指令“init_worker_by_lua_file”, ngx_http_lua_init_worker_by_file() */
 
    ngx_http_lua_balancer_peer_data_t  *balancer_peer_data;
                    /* balancer_by_lua does not support yielding and
                     * there cannot be any conflicts among concurrent requests,
                     * thus it is safe to store the peer data in the main conf.
                     */

    ngx_uint_t           shm_zones_inited;           /* 已初始化的共享内存数 */

    ngx_http_lua_sema_mm_t         *sema_mm;

    unsigned             requires_header_filter:1;   /* 拥有配置指令header_filter_by_lua* */
    unsigned             requires_body_filter:1;     /* body_filter_by_lua* */
    unsigned             requires_capture_filter:1;  /* content_by_lua* */
    unsigned             requires_rewrite:1;         /* rewrite_by_lua* */
    unsigned             requires_access:1;          /* access_by_lua* */
    unsigned             requires_log:1;             /* log_by_lua* */
    unsigned             requires_shm:1;             /* lua_shared_dict */
};


union ngx_http_lua_srv_conf_u {
    /* http{server{}}层级, 控制downstream SSL链路 */
#if (NGX_HTTP_SSL)
    struct {
        ngx_http_lua_srv_conf_handler_pt     ssl_cert_handler;
        ngx_str_t ssl_cert_src;       /* "ssl_certificate_by_lua_file" */
        u_char *ssl_cert_src_key;     /* ngx_http_lua_ssl_cert_handler_file() */

        ngx_http_lua_srv_conf_handler_pt     ssl_sess_store_handler;
        ngx_str_t ssl_sess_store_src;  /* "ssl_session_store_by_lua_file" */
        u_char *ssl_sess_store_src_key;/* ngx_http_lua_ssl_sess_store_handler_file() */

        ngx_http_lua_srv_conf_handler_pt     ssl_sess_fetch_handler;
        ngx_str_t ssl_sess_fetch_src;  /* "ssl_session_fetch_by_lua_file" */
        u_char *ssl_sess_fetch_src_key;/* ngx_http_lua_ssl_sess_fetch_handler_file() */
    } srv;
#endif
    
    /* http{upstream{}}层级，对应配置指令“balancer_by_lua_file” */
    struct {
        ngx_str_t           src;                   /* 脚本文件名 */
        u_char             *src_key;               /* "nhli_" + md5(->src) */
        ngx_http_lua_srv_conf_handler_pt  handler; /* ngx_http_lua_balancer_handler_file() */
    } balancer;
};

/* lua nginx模块儿location环境 */
typedef struct {
#if (NGX_HTTP_SSL)
    ngx_ssl_t  *ssl;  /* SSL环境，用于cosocket主动发起SSL连接，做为客户端，shared by SSL cosockets */
    ngx_uint_t ssl_protocols;           /* "lua_ssl_protocols SSLv3 TLS1.2", 参考 ngx_http_lua_ssl_protocols[] */
    ngx_str_t  ssl_ciphers;             /* "lua_ssl_ciphers DEFAULT" */
    ngx_uint_t ssl_verify_depth;        /* "lua_ssl_verify_depth 1" */
    ngx_str_t  ssl_trusted_certificate; /* "lua_ssl_trusted_certificate <file>" */
    ngx_str_t  ssl_crl;                 /* "lua_ssl_crl <file>" */
#endif

    ngx_flag_t force_read_body;    /* 对应配置lua_need_request_body，是否强制读取请求体; 
                                      推荐使用ngx.req.read_body()/ngx.req.discard_body(), 更灵活 */
    ngx_flag_t  enable_code_cache; /* 对应配置指令“lua_code_cache on/off”，是否使能code cache */
    ngx_flag_t              http10_buffering;

    /* 各阶段处理句柄，对应rewrite/access/content/log/header_filter/body_filter_by_lua_file */
    ngx_http_handler_pt rewrite_handler;       /* ngx_http_lua_rewrite_handler_file() */
    ngx_http_handler_pt access_handler;        /* ngx_http_lua_access_handler_file() */
    ngx_http_handler_pt content_handler;       /* ngx_http_lua_content_handler_file() */
    ngx_http_handler_pt log_handler;           /* ngx_http_lua_log_handler_file() */
    ngx_http_handler_pt header_filter_handler; /* ngx_http_lua_header_filter_file() */
    ngx_http_output_body_filter_pt body_filter_handler; /* ngx_http_lua_body_filter_file() */

    u_char                  *rewrite_chunkname;
    ngx_http_complex_value_t rewrite_src;    /*  rewrite_by_lua
                                                inline script/script
                                                file path */

    u_char                  *rewrite_src_key; /* cached key for rewrite_src */

    u_char                  *access_chunkname;
    ngx_http_complex_value_t access_src;     /*  access_by_lua
                                                inline script/script
                                                file path */

    u_char                  *access_src_key; /* cached key for access_src */

    u_char                  *content_chunkname; /* 自生成的内部程序块儿名 */
    ngx_http_complex_value_t content_src;       /* 由content_by_lua*系列配置指定
                                                   的lua代码串，或lua脚本路径 */
    u_char                 *content_src_key;    /* content_src的MD5值，用作注册表中编译后代码缓存块儿的key */


    u_char                      *log_chunkname;
    ngx_http_complex_value_t     log_src;     /* log_by_lua inline script/script
                                                 file path */

    u_char                      *log_src_key; /* cached key for log_src */

    ngx_http_complex_value_t header_filter_src;  /*  header_filter_by_lua
                                                     inline script/script
                                                     file path */

    u_char                 *header_filter_src_key;
                                    /* cached key for header_filter_src */


    ngx_http_complex_value_t         body_filter_src;
    u_char                          *body_filter_src_key;

    ngx_msec_t keepalive_timeout; /* "lua_socket_keepalive_timeout" */
    ngx_msec_t connect_timeout;   /* "lua_socket_connect_timeout" */
    ngx_msec_t send_timeout;      /* "lua_socket_send_timeout" */
    ngx_msec_t read_timeout;      /* "lua_socket_read_timeout" */

    size_t     send_lowat;        /* "lua_socket_send_lowat" */
    size_t     buffer_size;       /* "lua_socket_buffer_size" */

    ngx_uint_t pool_size;         /* "lua_socket_pool_size" */

    ngx_flag_t transform_underscores_in_resp_headers;
    ngx_flag_t log_socket_errors;

    ngx_flag_t check_client_abort;/* "lua_check_client_abort", 检查client是否关闭连接 */
    ngx_flag_t use_default_type;  /* "lua_use_default_type" */
} ngx_http_lua_loc_conf_t;


typedef enum {
    NGX_HTTP_LUA_USER_CORO_NOP      = 0,
    NGX_HTTP_LUA_USER_CORO_RESUME   = 1,
    NGX_HTTP_LUA_USER_CORO_YIELD    = 2,
    NGX_HTTP_LUA_USER_THREAD_RESUME = 3
} ngx_http_lua_user_coro_op_t;


typedef enum {
    NGX_HTTP_LUA_CO_RUNNING   = 0, /* coroutine running */
    NGX_HTTP_LUA_CO_SUSPENDED = 1, /* coroutine suspended */
    NGX_HTTP_LUA_CO_NORMAL    = 2, /* coroutine normal */
    NGX_HTTP_LUA_CO_DEAD      = 3, /* coroutine dead */
    NGX_HTTP_LUA_CO_ZOMBIE    = 4, /* coroutine zombie */
} ngx_http_lua_co_status_t;


typedef struct ngx_http_lua_co_ctx_s  ngx_http_lua_co_ctx_t;

typedef struct ngx_http_lua_posted_thread_s  ngx_http_lua_posted_thread_t;

struct ngx_http_lua_posted_thread_s {
    ngx_http_lua_co_ctx_t               *co_ctx;
    ngx_http_lua_posted_thread_t        *next;
};


enum {
    NGX_HTTP_LUA_SUBREQ_TRUNCATED = 1
};

/* 跟踪特定阶段的Lua协程环境 */
struct ngx_http_lua_co_ctx_s {
    void  *data;        /* ngx_http_lua_socket_tcp_upstream_t, user state for cosockets */

    lua_State  *co;     /* 通过lua_newthread()创建的协程栈 */
    ngx_http_lua_co_ctx_t *parent_co_ctx;   /* 对应的父协程 */

    ngx_http_lua_posted_thread_t *zombie_child_threads;  /* 子协程主动释放后，加入此 */

    ngx_http_cleanup_pt cleanup;      /*  */

    ngx_int_t               *sr_statuses; /* all capture subrequest statuses */

    ngx_http_headers_out_t **sr_headers;

    ngx_str_t               *sr_bodies;   /* all captured subrequest bodies */

    uint8_t                 *sr_flags;

    unsigned                 nsubreqs;  /* number of subrequests of the
                                         * current request */

    unsigned                 pending_subreqs; /* number of subrequests being
                                                 waited */

    ngx_event_t              sleep;  /* used for ngx.sleep */

    ngx_queue_t              sem_wait_queue;

#ifdef NGX_LUA_USE_ASSERT
    int co_top;         /* 栈顶元素索引，仅用于恢复执行时，堆栈健康检查
                           stack top after yielding/creation, only for sanity checks */
#endif

    int co_ref;         /* 全局Lua虚拟机全局注册表ngx_http_lua_coroutines_key项
                           中，此协程对应的索引，以防止此协程的栈被GC释放
                           reference to anchor the thread coroutines (entry 
                           coroutine and user threads) in the Lua registry,
                           preventing the thread coroutine from beging collected
                           by the Lua GC */

    unsigned waited_by_parent:1;  /* whether being waited by a parent coroutine */

    unsigned co_status:3;  /* 协程的状态，如 NGX_HTTP_LUA_CO_DEAD */

    unsigned                 flushing:1; /* indicates whether the current
                                            coroutine is waiting for
                                            ngx.flush(true) */

    unsigned is_uthread:1; /* whether the current coroutine is a user thread */

    unsigned thread_spawn_yielded:1; /* yielded from the ngx.thread.spawn() call */
    unsigned sem_resume_status:1;
};

/* 描述Lua虚拟机 */
typedef struct {
    lua_State       *vm;            /* Lua虚拟机栈 */
    ngx_int_t        count;         /* 引用计数 */
} ngx_http_lua_vm_state_t;

/* 每请求的Lua上下文执行环境，是沟通起nginx的C环境和Lua环境的桥梁 */
typedef struct ngx_http_lua_ctx_s {
    ngx_http_lua_vm_state_t *vm_state; /* 对应配置指令lua_coce_cache off
                                          每个请求对应一个新的虚拟机，以
                                          便于每次都重新加载脚本 */
    ngx_http_request_t *request;       /* 对应当前的HTTP请求 */
    ngx_http_handler_pt resume_handler;/* 执行环境恢复句柄，
                                            内容处理阶段，待读取报文体=ngx_http_lua_read_body_resume()
                                            非阻塞睡眠ngx.sleep()=ngx_http_lua_sleep_resume()
                                            =ngx_http_lua_sema_resume()
                                            =ngx_http_lua_on_abort_resume()
                                            =ngx_http_lua_socket_tcp_conn_resume()
                                            =ngx_http_lua_socket_tcp_read_resume()
                                            =ngx_http_lua_socket_tcp_write_resume()
                                            =ngx_http_lua_socket_udp_resume()
                                            =ngx_http_lua_subrequest_resume() */

    ngx_http_lua_co_ctx_t *cur_co_ctx; /* 当前协程的执行环境，初始化为&entry_co_ctx */

    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */
    ngx_list_t *user_co_ctx;           /* coroutine contexts for user
                                                 coroutines */

    ngx_http_lua_co_ctx_t entry_co_ctx;/* 主(入口)协程执行环境，coroutine context 
                                          for the entry coroutine */

    ngx_http_lua_co_ctx_t   *on_abort_co_ctx; /* coroutine context for the
                                                 on_abort thread */

    int                      ctx_ref;  /*  reference to anchor
                                           request ctx data in lua
                                           registry */

    unsigned                 flushing_coros; /* number of coroutines waiting on
                                                ngx.flush(true) */

    ngx_chain_t             *out;  /* buffered output chain for HTTP 1.0 */
    ngx_chain_t             *free_bufs;
    ngx_chain_t             *busy_bufs;
    ngx_chain_t             *free_recv_bufs;

    ngx_http_cleanup_pt     *cleanup;      /* 协程资源清理句柄, 设置为
                                              ngx_http_lua_request_cleanup_handler() */

    ngx_http_cleanup_t      *free_cleanup; /* free list of cleanup records */

    ngx_chain_t             *body; /* buffered subrequest response body
                                      chains */

    ngx_chain_t            **last_body; /* for the "body" field */

    ngx_str_t                exec_uri;
    ngx_str_t                exec_args;

    ngx_int_t                exit_code;

    void                    *downstream;  /* can be either
                                             ngx_http_lua_socket_tcp_upstream_t
                                             or ngx_http_lua_co_ctx_t */

    ngx_uint_t               index;              /* index of the current
                                                    subrequest in its parent
                                                    request */

    ngx_http_lua_posted_thread_t   *posted_threads;
                        /* 待执行的协程列表 */

    int  uthreads;      /* 活跃的子协程数，number of active user threads */

    uint16_t context;   /* 当前Lua代码块儿所处的指令环境，
                           如 NGX_HTTP_LUA_CONTEXT_CONTENT

                           the current running directive context
                           (or running phase) for the current Lua chunk */

    unsigned                 run_post_subrequest:1; /* whether it has run
                                                       post_subrequest
                                                       (for subrequests only) */

    unsigned  waiting_more_body:1; /* 1: 等待后续报文体
                                      0: 不需读取报文体，一般读取完毕后置位 */

    unsigned  co_op:2;  /* NGX_HTTP_LUA_USER_CORO_NOP, coroutine API operation */

    unsigned         exited:1;

    unsigned         eof:1;             /*  1: last_buf has been sent;
                                            0: last_buf not sent yet */

    unsigned         capture:1;  /*  1: response body of current request
                                        is to be captured by the lua
                                        capture filter,
                                     0: not to be captured */


    unsigned  read_body_done:1;    /* 1: 请求报文体已经读取完毕
                                      0: 请求体尚未读取完毕 */

    unsigned         headers_set:1; /* whether the user has set custom
                                       response headers */

    unsigned         entered_rewrite_phase:1;
    unsigned         entered_access_phase:1;
    unsigned         entered_content_phase:1; /* 是否已经进入内容处理阶段 */

    unsigned         buffering:1; /* HTTP 1.0 response body buffering flag */

    unsigned         no_abort:1; /* prohibit "world abortion" via ngx.exit()
                                    and etc */

    unsigned         header_sent:1; /* r->header_sent is not sufficient for
                                     * this because special header filters
                                     * like ngx_image_filter may intercept
                                     * the header. so we should always test
                                     * both flags. see the test case in
                                     * t/020-subrequest.t */

    unsigned         seen_last_in_filter:1;  /* used by body_filter_by_lua* */
    unsigned         seen_last_for_subreq:1; /* used by body capture filter */
    unsigned         writing_raw_req_socket:1; /* used by raw downstream
                                                  socket */
    unsigned         acquired_raw_req_socket:1;  /* whether a raw req socket
                                                    is acquired */
    unsigned         seen_body_data:1;
} ngx_http_lua_ctx_t;


typedef struct ngx_http_lua_header_val_s  ngx_http_lua_header_val_t;


typedef ngx_int_t (*ngx_http_lua_set_header_pt)(ngx_http_request_t *r,
    ngx_http_lua_header_val_t *hv, ngx_str_t *value);


struct ngx_http_lua_header_val_s {
    ngx_http_complex_value_t                value;
    ngx_uint_t                              hash;
    ngx_str_t                               key;
    ngx_http_lua_set_header_pt              handler;
    ngx_uint_t                              offset;
    unsigned                                no_override;
};


typedef struct {
    ngx_str_t                               name;
    ngx_uint_t                              offset;
    ngx_http_lua_set_header_pt              handler;

} ngx_http_lua_set_header_t;


extern ngx_module_t ngx_http_lua_module;
extern ngx_http_output_header_filter_pt ngx_http_lua_next_header_filter;
extern ngx_http_output_body_filter_pt ngx_http_lua_next_body_filter;


#endif /* _NGX_HTTP_LUA_COMMON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
