
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "nginx.h"
#include "ngx_http_lua_directive.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_pcrefix.h"
#include "ngx_http_lua_regex.h"
#include "ngx_http_lua_args.h"
#include "ngx_http_lua_uri.h"
#include "ngx_http_lua_req_body.h"
#include "ngx_http_lua_headers.h"
#include "ngx_http_lua_output.h"
#include "ngx_http_lua_time.h"
#include "ngx_http_lua_control.h"
#include "ngx_http_lua_ndk.h"
#include "ngx_http_lua_subrequest.h"
#include "ngx_http_lua_log.h"
#include "ngx_http_lua_variable.h"
#include "ngx_http_lua_string.h"
#include "ngx_http_lua_misc.h"
#include "ngx_http_lua_consts.h"
#include "ngx_http_lua_req_method.h"
#include "ngx_http_lua_shdict.h"
#include "ngx_http_lua_coroutine.h"
#include "ngx_http_lua_socket_tcp.h"
#include "ngx_http_lua_socket_udp.h"
#include "ngx_http_lua_sleep.h"
#include "ngx_http_lua_setby.h"
#include "ngx_http_lua_headerfilterby.h"
#include "ngx_http_lua_bodyfilterby.h"
#include "ngx_http_lua_logby.h"
#include "ngx_http_lua_phase.h"
#include "ngx_http_lua_probe.h"
#include "ngx_http_lua_uthread.h"
#include "ngx_http_lua_contentby.h"
#include "ngx_http_lua_timer.h"
#include "ngx_http_lua_config.h"
#include "ngx_http_lua_worker.h"
#include "ngx_http_lua_socket_tcp.h"
#include "ngx_http_lua_ssl_certby.h"
#include "ngx_http_lua_ssl.h"


#if 1
#undef ngx_http_lua_probe_info
#define ngx_http_lua_probe_info(msg)
#endif


#ifndef NGX_HTTP_LUA_BT_DEPTH
#define NGX_HTTP_LUA_BT_DEPTH  22
#endif


#ifndef NGX_HTTP_LUA_BT_MAX_COROS
#define NGX_HTTP_LUA_BT_MAX_COROS  5
#endif

/* 全局注册表 */
char ngx_http_lua_code_cache_key;        /* 表，缓存Lua脚本代码，以加速执行效率 */
char ngx_http_lua_regex_cache_key;       /**/
char ngx_http_lua_socket_pool_key;       /* 表，记录cosocket链路缓存, ngx_http_lua_socket_pool_t */
char ngx_http_lua_coroutines_key;        /* 表，记录“执行Lua脚本的协程” */
char ngx_http_lua_headers_metatable_key; /**/


ngx_uint_t  ngx_http_lua_location_hash = 0;       /**/
ngx_uint_t  ngx_http_lua_content_length_hash = 0; /**/


static ngx_int_t ngx_http_lua_send_http10_headers(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static void ngx_http_lua_init_registry(lua_State *L, ngx_log_t *log);
static void ngx_http_lua_init_globals(lua_State *L, ngx_cycle_t *cycle,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log);
static void ngx_http_lua_set_path(ngx_cycle_t *cycle, lua_State *L, int tab_idx,
    const char *fieldname, const char *path, const char *default_path,
    ngx_log_t *log);
static ngx_int_t ngx_http_lua_handle_exec(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static ngx_int_t ngx_http_lua_handle_exit(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static ngx_int_t ngx_http_lua_handle_rewrite_jump(lua_State *L,
    ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx);
static int ngx_http_lua_thread_traceback(lua_State *L, lua_State *co,
    ngx_http_lua_co_ctx_t *coctx);
static void ngx_http_lua_inject_ngx_api(lua_State *L,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log);
static void ngx_http_lua_inject_arg_api(lua_State *L);
static int ngx_http_lua_param_get(lua_State *L);
static int ngx_http_lua_param_set(lua_State *L);
static ngx_int_t ngx_http_lua_output_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_lua_send_special(ngx_http_request_t *r,
    ngx_uint_t flags);
static void ngx_http_lua_finalize_threads(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, lua_State *L);
static ngx_int_t ngx_http_lua_post_zombie_thread(ngx_http_request_t *r,
    ngx_http_lua_co_ctx_t *parent, ngx_http_lua_co_ctx_t *thread);
static void ngx_http_lua_cleanup_zombie_child_uthreads(ngx_http_request_t *r,
    lua_State *L, ngx_http_lua_ctx_t *ctx, ngx_http_lua_co_ctx_t *coctx);
static ngx_int_t ngx_http_lua_on_abort_resume(ngx_http_request_t *r);
static void ngx_http_lua_close_fake_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_flush_pending_output(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static ngx_int_t
    ngx_http_lua_process_flushing_coroutines(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static lua_State *ngx_http_lua_new_state(lua_State *parent_vm,
    ngx_cycle_t *cycle, ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log);
static int ngx_http_lua_get_raw_phase_context(lua_State *L);


#ifndef LUA_PATH_SEP
#define LUA_PATH_SEP ";"
#endif

#define AUX_MARK "\1"

/* 利用配置信息，设置package.path/package.cpath */
static void
ngx_http_lua_set_path(ngx_cycle_t *cycle, lua_State *L, int tab_idx,
    const char *fieldname, const char *path, const char *default_path,
    ngx_log_t *log)
{
    const char          *tmp_path;
    const char          *prefix;

    /* XXX here we use some hack to simplify string manipulation */
    tmp_path = luaL_gsub(L, path, LUA_PATH_SEP LUA_PATH_SEP,
                         LUA_PATH_SEP AUX_MARK LUA_PATH_SEP);

    /* 替换$prefix/${prefix} */
    lua_pushlstring(L, (char *) cycle->prefix.data, cycle->prefix.len);
    prefix = lua_tostring(L, -1);
    tmp_path = luaL_gsub(L, tmp_path, "$prefix", prefix);
    tmp_path = luaL_gsub(L, tmp_path, "${prefix}", prefix);
    lua_pop(L, 3);

    dd("tmp_path path: %s", tmp_path);

    /* 替换;;为默认搜索路径 */
#if (NGX_DEBUG)
    tmp_path =
#else
    (void)
#endif
        luaL_gsub(L, tmp_path, AUX_MARK, default_path);

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua setting lua package.%s to \"%s\"", fieldname, tmp_path);
#endif

    /* 此步骤后，和此函数调用初相比；栈顶多了一个元素，存放着路径字符串；
       且已经替换${prefix}，并且替换了;;默认搜索路径 */
    lua_remove(L, -2);

    /* 更新对应的package.path；因为多压入了一个字符串，因此需要更新负值索引；
       fix negative index as there's new data on stack */
    tab_idx = (tab_idx < 0) ? (tab_idx - 1) : tab_idx;
    lua_setfield(L, tab_idx, fieldname);
}


/**
 * Create new table and set _G field to itself.
 *
 * After:
 *         | new table | <- top
 *         |    ...    |
 * */
/* 创建新表，并设置_G元素为自身，即全局表 */
void
ngx_http_lua_create_new_globals_table(lua_State *L, int narr, int nrec)
{
    lua_createtable(L, narr, nrec + 1);   /* 创建特定大小的表，并放置到栈顶 */
    lua_pushvalue(L, -1);                 /* 复制新建表，放置到栈顶(实际内存未复制，应该只复制了地址) */
    lua_setfield(L, -2, "_G");            /* 新建表["_G"] = 新建表 */
}

/* 创建Lua虚拟机实例 */
static lua_State *
ngx_http_lua_new_state(lua_State *parent_vm, ngx_cycle_t *cycle,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log)
{
    lua_State       *L;
    const char      *old_path;
    const char      *new_path;
    size_t           old_path_len;
    const char      *old_cpath;
    const char      *new_cpath;
    size_t           old_cpath_len;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "lua creating new vm state");

    /* 创建Lua虚拟机 */
    L = luaL_newstate();
    if (L == NULL) {
        return NULL;
    }

    /* 打开标准lua库 */
    luaL_openlibs(L);

    /* 修改全局package库的搜索路径，对应配置指令“lua_package_path”、“lua_package_cpath”

       <NOTE> The package library provides basic facilities for loading 
              modules in Lua. It exports one function directly in the global 
              environment: require. Everything else is exported in a table package.  */
    lua_getglobal(L, "package");
    if (!lua_istable(L, -1)) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "the \"package\" table does not exist");
        return NULL;
    }

    if (parent_vm) {               /* 存在父环境，则利用父环境初始化 */
        lua_getglobal(parent_vm, "package");
        lua_getfield(parent_vm, -1, "path");
        old_path = lua_tolstring(parent_vm, -1, &old_path_len);
        lua_pop(parent_vm, 1);

        lua_pushlstring(L, old_path, old_path_len);
        lua_setfield(L, -2, "path");

        lua_getfield(parent_vm, -1, "cpath");
        old_path = lua_tolstring(parent_vm, -1, &old_path_len);
        lua_pop(parent_vm, 2);

        lua_pushlstring(L, old_path, old_path_len);
        lua_setfield(L, -2, "cpath");

    } else {                       /* 不存在父环境，则利用“配置信息＋默认信息”初始化 */
#ifdef LUA_DEFAULT_PATH
#   define LUA_DEFAULT_PATH_LEN (sizeof(LUA_DEFAULT_PATH) - 1)
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "lua prepending default package.path with %s",
                       LUA_DEFAULT_PATH);

        lua_pushliteral(L, LUA_DEFAULT_PATH ";"); /* package default */
        lua_getfield(L, -2, "path"); /* package default old */
        old_path = lua_tolstring(L, -1, &old_path_len);
        lua_concat(L, 2); /* package new */
        lua_setfield(L, -2, "path"); /* package */
#endif

#ifdef LUA_DEFAULT_CPATH
#   define LUA_DEFAULT_CPATH_LEN (sizeof(LUA_DEFAULT_CPATH) - 1)
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "lua prepending default package.cpath with %s",
                       LUA_DEFAULT_CPATH);

        lua_pushliteral(L, LUA_DEFAULT_CPATH ";"); /* package default */
        lua_getfield(L, -2, "cpath"); /* package default old */
        old_cpath = lua_tolstring(L, -1, &old_cpath_len);
        lua_concat(L, 2); /* package new */
        lua_setfield(L, -2, "cpath"); /* package */
#endif

        if (lmcf->lua_path.len != 0) {
            lua_getfield(L, -1, "path"); /* get original package.path */
            old_path = lua_tolstring(L, -1, &old_path_len);

            dd("old path: %s", old_path);

            lua_pushlstring(L, (char *) lmcf->lua_path.data,
                            lmcf->lua_path.len);
            new_path = lua_tostring(L, -1);

            ngx_http_lua_set_path(cycle, L, -3, "path", new_path, old_path,
                                  log);

            lua_pop(L, 2);
        }

        if (lmcf->lua_cpath.len != 0) {
            lua_getfield(L, -1, "cpath"); /* get original package.cpath */
            old_cpath = lua_tolstring(L, -1, &old_cpath_len);

            dd("old cpath: %s", old_cpath);

            lua_pushlstring(L, (char *) lmcf->lua_cpath.data,
                            lmcf->lua_cpath.len);
            new_cpath = lua_tostring(L, -1);

            ngx_http_lua_set_path(cycle, L, -3, "cpath", new_cpath, old_cpath,
                                  log);


            lua_pop(L, 2);
        }
    }
    lua_pop(L, 1);                /* 弹出标准库package表，恢复堆栈 */

    /* 初始化Lua的注册表，用于保存模块儿间共享的数据, 键值 ngx_http_lua_code_cache_key */
    ngx_http_lua_init_registry(L, log);

    /* 暴露全局变量ndk、ngx、__ngx_cycle */
    ngx_http_lua_init_globals(L, cycle, lmcf, log);

    return L;
}

/* 创建新协程，此协程继承了老Lua虚拟机环境L的全局变量，并创建了自己的
   全局空表；并通过注册表项 &ngx_http_lua_coroutines_key 的协程记录表记录
   到老Lua环境中 */
lua_State *
ngx_http_lua_new_thread(ngx_http_request_t *r, lua_State *L, int *ref)
{
    int              base;
    lua_State       *co;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua creating new thread");

    base = lua_gettop(L);                   /* 获取栈顶索引 */

    lua_pushlightuserdata(L, &ngx_http_lua_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);       /* 获取注册表中，索引为
                                               &ngx_http_lua_coroutines_key的值，
                                               即协程索引表；压入栈 */
    /* 创建线程，实质上为协程；参考Lua5.1手册，lua_newthread()函数的描述如下：
          Creates a new thread, pushes it on the stack, and returns a pointer
          to a lua_State that represents this new thread. The new state returned
          by this function shares with the original state all global objects 
          (such as tables), but has an independent execution stack
          新建立的线程，和原执行环境共享所有的全局表，但拥有不同的执行栈

        <TAKE CARE!!!>
        正是拥有相同的全局表，因此可通过"加载特殊模块儿"的方式在worker的不同
        请求间达到数据共享的目的；此处的模块儿特殊之处为，它专门用于存储数据，
        而不是处理请求 */
    co = lua_newthread(L);

    /*  {{{ inherit coroutine's globals to main thread's globals table
     *  for print() function will try to find tostring() in current
     *  globals table.
     */
    /* 为新建线程创建新全局空表，其中["_G"]指向自身 */
    ngx_http_lua_create_new_globals_table(co, 0, 0);
    
    /* 新建表，做为上述表的元表，并且其["__index"]为当前协程的全局变量表(索
       引为LUA_GLOBALSINDEX)，注意此全局变量表也即外层L的全局变量表(后续将
       被替换) */
    lua_createtable(co, 0, 1);
    ngx_http_lua_get_globals_table(co);
    lua_setfield(co, -2, "__index");
    lua_setmetatable(co, -2);

    /* 由于lua_setmetatable()/lua_setfield()都涉及到弹出栈顶元素；因此
       此时栈顶为ngx_http_lua_create_new_globals_table()新建的表；把它
       设置为此新建线程的全局表(索引LUA_GLOBALSINDEX) */
    ngx_http_lua_set_globals_table(co);
    /* <TAKECARE!!!>此函数执行完毕后，其全局表(索引LUA_GLOBALSINDEX)为新建
                    表，其[_G]指向自身；其元表也为新建表，元表[__index]指
                    向父协程(即L)的全局表 */
    /*  }}} */

    /* 在L栈索引为-2的表中创建栈顶元素的索引
          -2为全局注册表中键“&ngx_http_lua_coroutines_key”对应的表
          栈顶为新创建的协程结构
       因此，结果是在L全局注册表对应特定键的表中，添加了新创建协程的索引 */
    *ref = luaL_ref(L, -2);     
    if (*ref == LUA_NOREF) {
        lua_settop(L, base);  /* restore main thread stack */
        return NULL;
    }

    lua_settop(L, base);      /* 恢复L的栈 */
    return co;
}

/* 从全局注册表删除，从此此协程不可以再索引 */
void
ngx_http_lua_del_thread(ngx_http_request_t *r, lua_State *L,
    ngx_http_lua_ctx_t *ctx, ngx_http_lua_co_ctx_t *coctx)
{
    if (coctx->co_ref == LUA_NOREF) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua deleting light thread");

    lua_pushlightuserdata(L, &ngx_http_lua_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);

    ngx_http_lua_probe_thread_delete(r, coctx->co, ctx);

    luaL_unref(L, -1, coctx->co_ref);
    coctx->co_ref = LUA_NOREF;
    coctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    lua_pop(L, 1);
}


u_char *
ngx_http_lua_rebase_path(ngx_pool_t *pool, u_char *src, size_t len)
{
    u_char     *p;
    ngx_str_t   dst;

    dst.data = ngx_palloc(pool, len + 1);
    if (dst.data == NULL) {
        return NULL;
    }

    dst.len = len;

    p = ngx_copy(dst.data, src, len);
    *p = '\0';

    if (ngx_get_full_name(pool, (ngx_str_t *) &ngx_cycle->prefix, &dst)
        != NGX_OK)
    {
        return NULL;
    }

    return dst.data;
}


ngx_int_t
ngx_http_lua_send_header_if_needed(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t            rc;

    dd("send header if needed: %d", r->header_sent || ctx->header_sent);

    if (!r->header_sent && !ctx->header_sent) {
        if (r->headers_out.status == 0) {
            r->headers_out.status = NGX_HTTP_OK;
        }

        if (!ctx->headers_set && ngx_http_lua_set_content_type(r) != NGX_OK) {
            return NGX_ERROR;
        }

        if (!ctx->headers_set) {
            ngx_http_clear_content_length(r);
            ngx_http_clear_accept_ranges(r);
        }

        if (!ctx->buffering) {
            dd("sending headers");
            rc = ngx_http_send_header(r);
            ctx->header_sent = 1;
            return rc;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_lua_send_chain_link(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t                     rc;
    ngx_chain_t                  *cl;
    ngx_chain_t                 **ll;
    ngx_http_lua_loc_conf_t      *llcf;

#if 1
    if (ctx->acquired_raw_req_socket || ctx->eof) {
        dd("ctx->eof already set or raw req socket already acquired");
        return NGX_OK;
    }
#endif

    if ((r->method & NGX_HTTP_HEAD) && !r->header_only) {
        r->header_only = 1;
    }

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (llcf->http10_buffering
        && !ctx->buffering
        && !r->header_sent
        && !ctx->header_sent
        && r->http_version < NGX_HTTP_VERSION_11
        && r->headers_out.content_length_n < 0)
    {
        ctx->buffering = 1;
    }

    rc = ngx_http_lua_send_header_if_needed(r, ctx);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (r->header_only) {
        ctx->eof = 1;

        if (ctx->buffering) {
            return ngx_http_lua_send_http10_headers(r, ctx);
        }

        return rc;
    }

    if (in == NULL) {
        dd("last buf to be sent");

#if 1
        if (!r->request_body && r == r->main) {
            if (ngx_http_discard_request_body(r) != NGX_OK) {
                return NGX_ERROR;
            }
        }
#endif

        if (ctx->buffering) {
            rc = ngx_http_lua_send_http10_headers(r, ctx);
            if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            if (ctx->out) {

                rc = ngx_http_lua_output_filter(r, ctx->out);

                if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                    return rc;
                }

                ctx->out = NULL;
            }
        }

#if defined(nginx_version) && nginx_version <= 8004

        /* earlier versions of nginx does not allow subrequests
           to send last_buf themselves */
        if (r != r->main) {
            return NGX_OK;
        }

#endif

        ctx->eof = 1;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua sending last buf of the response body");

        rc = ngx_http_lua_send_special(r, NGX_HTTP_LAST);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_OK;
    }

    /* in != NULL */

    if (ctx->buffering) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua buffering output bufs for the HTTP 1.0 request");

        for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
            ll = &cl->next;
        }

        *ll = in;

        return NGX_OK;
    }

    return ngx_http_lua_output_filter(r, in);
}


static ngx_int_t
ngx_http_lua_send_special(ngx_http_request_t *r, ngx_uint_t flags)
{
    ngx_int_t            rc;
    ngx_http_request_t  *ar; /* active request */

    ar = r->connection->data;

    if (ar != r) {

        /* bypass ngx_http_postpone_filter_module */

        r->connection->data = r;
        rc = ngx_http_send_special(r, flags);
        r->connection->data = ar;
        return rc;
    }

    return ngx_http_send_special(r, flags);
}


static ngx_int_t
ngx_http_lua_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t            rc;
    ngx_http_lua_ctx_t  *ctx;
    ngx_http_request_t  *ar; /* active request */

    ar = r->connection->data;

    if (ar != r) {

        /* bypass ngx_http_postpone_filter_module */

        r->connection->data = r;
        rc = ngx_http_output_filter(r, in);
        r->connection->data = ar;
        return rc;
    }

    rc = ngx_http_output_filter(r, in);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

#if nginx_version >= 1001004
    ngx_chain_update_chains(r->pool,
#else
    ngx_chain_update_chains(
#endif
                            &ctx->free_bufs, &ctx->busy_bufs, &in,
                            (ngx_buf_tag_t) &ngx_http_lua_module);

    return rc;
}


static ngx_int_t
ngx_http_lua_send_http10_headers(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    off_t                size;
    ngx_chain_t         *cl;
    ngx_int_t            rc;

    if (r->header_sent || ctx->header_sent) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua sending HTTP 1.0 response headers");

    if (r->header_only) {
        goto send;
    }

    if (r->headers_out.content_length == NULL) {
        for (size = 0, cl = ctx->out; cl; cl = cl->next) {
            size += ngx_buf_size(cl->buf);
        }

        r->headers_out.content_length_n = size;

        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
        }
    }

send:

    rc = ngx_http_send_header(r);
    ctx->header_sent = 1;
    return rc;
}

/* 初始化注册表，存放全局变量的表，可用于保存模块儿间共享的数据
       只能被C代码访问
       位于虚拟索引LUA_REGISTRYINDEX上
       key值需要谨慎选择，以避免冲突(可选择变量地址，由链接器保证唯一)

   示例：保存字符串
       const static char *key;
       lua_pushlightuserdata(L, (void*) &key);   压入地址
       lua_pushstring(L, mystr);                 压入值
       lua_settable(L, LUA_REGISTRYINDEX);       registry[&key] = mystr

   示例：检索字符串
       lua_pushlightuserdata(L, (void*) &key);   压入地址
       lua_gettable(L, LUA_REGISTRYINDEX);       检索值
       mystr = lua_tostring(L, -1);              转换成字符串
 */
static void
ngx_http_lua_init_registry(lua_State *L, ngx_log_t *log)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua initializing lua registry");

    /* {{{ register a table to anchor lua coroutines reliably:
     * {([int]ref) = [cort]} */
    /* 注册表：用于lua协程 */
    lua_pushlightuserdata(L, &ngx_http_lua_coroutines_key);
    lua_createtable(L, 0/* narr */, 32 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);  /* 类似于lua_settable(), 但效率更高 */
    /* }}} */

    /* create the registry entry for the Lua request ctx data table */
    /* 注册表：用于Lua请求环境数据 */
    lua_pushliteral(L, ngx_http_lua_ctx_tables_key);
    lua_createtable(L, 0, 32 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);

    /* create the registry entry for the Lua socket connection pool table */
    /* 注册表：Lua插口链接池 */
    lua_pushlightuserdata(L, &ngx_http_lua_socket_pool_key);
    lua_createtable(L, 0, 8 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);

#if (NGX_PCRE)
    /* create the registry entry for the Lua precompiled regex object cache */
    /* 注册表：预编译的Lua正则表达式缓存 */
    lua_pushlightuserdata(L, &ngx_http_lua_regex_cache_key);
    lua_createtable(L, 0, 16 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);
#endif

    /* {{{ register table to cache user code:
     * { [(string)cache_key] = <code closure> } */
    /* 注册表：Lua代码缓存 */
    lua_pushlightuserdata(L, &ngx_http_lua_code_cache_key);
    lua_createtable(L, 0, 8 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */
}

/* 初始化暴露到Lua环境中的全局变量，如ndk、ngx */
static void
ngx_http_lua_init_globals(lua_State *L, ngx_cycle_t *cycle,
    ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua initializing lua globals");
    
    /* 全局变量 __ngx_cycle, 指向当前的 ngx_cycle 配置*/
    lua_pushlightuserdata(L, cycle);
    lua_setglobal(L, "__ngx_cycle");

    /* 设置NDK包，全局变量 */
#if defined(NDK) && NDK
    ngx_http_lua_inject_ndk_api(L);
#endif /* defined(NDK) && NDK */

    /* 设置ngx包，全局变量 */
    ngx_http_lua_inject_ngx_api(L, lmcf, log);
}

/* 设置暴露到Lua环境的全局ngx表 */
static void
ngx_http_lua_inject_ngx_api(lua_State *L, ngx_http_lua_main_conf_t *lmcf,
    ngx_log_t *log)
{
    /* 新建表，最后命名为ngx */
    lua_createtable(L, 0 /* narr */, 116 /* nrec */);    /* ngx.* */

    /* ngx._phase_ctx，维护每请求的Lua代码块儿所处的阶段, ngx_http_lua_ctx_t->context */
    lua_pushcfunction(L, ngx_http_lua_get_raw_phase_context);
    lua_setfield(L, -2, "_phase_ctx");

    /* 初始化ngx.arg表 */
    ngx_http_lua_inject_arg_api(L);

    /* 初始化ngx.HTTP_GET/_xxx变量 */
    ngx_http_lua_inject_http_consts(L);
    
    /* 初始化ngx.OK/AGAIN/DONE/DECLINED/ERROR/null */
    ngx_http_lua_inject_core_consts(L);

    /* 注册日志函数, ngx.log/print() */
    ngx_http_lua_inject_log_api(L);
    
    /* 注册报文内容生成函数，ngx.say/send_headers/print/eof/flush() */
    ngx_http_lua_inject_output_api(L);

    /* 注册时间处理函数, ngx.utctime/time/now/... */
    ngx_http_lua_inject_time_api(L);

    /* 注册字符串处理函数，ngx.md5/encode_base64() */
    ngx_http_lua_inject_string_api(L);

    /* 注册控制、跳转函数，ngx.redirect/exec/on_abort()/... */
    ngx_http_lua_inject_control_api(log, L);

    /*注册子请求函数，ngx.capture/multi_capture/location() */
    ngx_http_lua_inject_subrequest_api(L);

    /* 注册睡眠等待函数，ngx.sleep() */
    ngx_http_lua_inject_sleep_api(L);

    /* 注册ngx.get_phase(), 获取当前Lua代码所处的执行阶段 */
    ngx_http_lua_inject_phase_api(L);

#if (NGX_PCRE)
    /* 注册pcre正则规则处理函数，ngx.find/sub/gmatch()/... */
    ngx_http_lua_inject_regex_api(L);
#endif

    /* 注册表ngx.req, 以获取或设置http信息,  包括头部、body等 */
    ngx_http_lua_inject_req_api(log, L);

    /* 注册ngx.header/ngx.resp表 */
    ngx_http_lua_inject_resp_header_api(L);
    ngx_http_lua_create_headers_metatable(log, L);

    /* 注册ngx.var表 */
    ngx_http_lua_inject_variable_api(L);

    /* 共享内存处理API，ngx.shared.DICT.xxx */
    ngx_http_lua_inject_shdict_api(lmcf, L);

    /* 原生态插口API，ngx.socket */
    ngx_http_lua_inject_socket_tcp_api(log, L);
    ngx_http_lua_inject_socket_udp_api(log, L);

    /* 注册ngx.thread表 */
    ngx_http_lua_inject_uthread_api(log, L);

    /* 注册ngx.timer表，定时器相关操作 */
    ngx_http_lua_inject_timer_api(L);

    /* 注册ngx.config表，以获取配置信息等 */
    ngx_http_lua_inject_config_api(L);

    /* 注册ngx.worker表，以获取worker进程信息 */
    ngx_http_lua_inject_worker_api(L);

    /* 初始化ngx的metadata表，提供其他变量的获取、添加功能，如ngx.ctx/ngx.status */
    ngx_http_lua_inject_misc_api(L);

    /* 加载ngx，设置package.loaded["ngx"] = {刚刚初始化的表} */
    lua_getglobal(L, "package"); /* ngx package */
    lua_getfield(L, -1, "loaded"); /* ngx package loaded */
    lua_pushvalue(L, -3); /* ngx package loaded ngx */
    lua_setfield(L, -2, "ngx"); /* ngx package loaded */
    lua_pop(L, 2);

    /* 设置表对应的全局名ngx，喔！！！ */
    lua_setglobal(L, "ngx");

    /* 注册协程API, coroutine.xxx */
    ngx_http_lua_inject_coroutine_api(log, L);
}


void
ngx_http_lua_discard_bufs(ngx_pool_t *pool, ngx_chain_t *in)
{
    ngx_chain_t         *cl;

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
    }
}


ngx_int_t
ngx_http_lua_add_copy_chain(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx,
    ngx_chain_t ***plast, ngx_chain_t *in, ngx_int_t *eof)
{
    ngx_chain_t     *cl;
    size_t           len;
    ngx_buf_t       *b;

    len = 0;
    *eof = 0;

    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            len += cl->buf->last - cl->buf->pos;
        }

        if (cl->buf->last_in_chain || cl->buf->last_buf) {
            *eof = 1;
        }
    }

    if (len == 0) {
        return NGX_OK;
    }

    cl = ngx_http_lua_chain_get_free_buf(r->connection->log, r->pool,
                                         &ctx->free_bufs, len);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    dd("chains get free buf: %d == %d", (int) (cl->buf->end - cl->buf->start),
       (int) len);

    b = cl->buf;

    while (in) {
        if (ngx_buf_in_memory(in->buf)) {
            b->last = ngx_copy(b->last, in->buf->pos,
                               in->buf->last - in->buf->pos);
        }

        in = in->next;
    }

    **plast = cl;
    *plast = &cl->next;

    return NGX_OK;
}


void
ngx_http_lua_reset_ctx(ngx_http_request_t *r, lua_State *L,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua reset ctx");

    ngx_http_lua_finalize_threads(r, ctx, L);

#if 0
    if (ctx->user_co_ctx) {
        /* no way to destroy a list but clean up the whole pool */
        ctx->user_co_ctx = NULL;
    }
#endif

    ngx_memzero(&ctx->entry_co_ctx, sizeof(ngx_http_lua_co_ctx_t));

    ctx->entry_co_ctx.co_ref = LUA_NOREF;

    ctx->entered_rewrite_phase = 0;
    ctx->entered_access_phase = 0;
    ctx->entered_content_phase = 0;

    ctx->exit_code = 0;
    ctx->exited = 0;
    ctx->resume_handler = ngx_http_lua_wev_handler;

    ngx_str_null(&ctx->exec_uri);
    ngx_str_null(&ctx->exec_args);

    ctx->co_op = 0;
}


/* post read callback for rewrite and access phases */
void
ngx_http_lua_generic_phase_post_read(ngx_http_request_t *r)
{
    ngx_http_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua post read for rewrite/access phases");

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    ctx->read_body_done = 1;

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}


void
ngx_http_lua_request_cleanup_handler(void *data)
{
    ngx_http_lua_ctx_t          *ctx = data;

    ngx_http_lua_request_cleanup(ctx, 0 /* forcible */);
}


void
ngx_http_lua_request_cleanup(ngx_http_lua_ctx_t *ctx, int forcible)
{
    lua_State                   *L;
    ngx_http_request_t          *r;
    ngx_http_lua_main_conf_t    *lmcf;

    /*  force coroutine handling the request quit */
    if (ctx == NULL) {
        dd("ctx is NULL");
        return;
    }

    r = ctx->request;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua request cleanup: forcible=%d", forcible);

    if (ctx->cleanup) {
        *ctx->cleanup = NULL;
        ctx->cleanup = NULL;
    }

    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

#if 1
    if (r->connection->fd == (ngx_socket_t) -1) {
        /* being a fake request */
        lmcf->running_timers--;
    }
#endif

    L = ngx_http_lua_get_lua_vm(r, ctx);

    ngx_http_lua_finalize_threads(r, ctx, L);
}


/*
 * description:
 *  run a Lua coroutine specified by ctx->cur_co_ctx->co
 * return value:
 *  NGX_AGAIN:      I/O interruption: r->main->count intact
 *  NGX_DONE:       I/O interruption: r->main->count already incremented by 1
 *  NGX_ERROR:      error
 *  >= 200          HTTP status code
 * 
 *  Lua协程的执行入口
 */
ngx_int_t
ngx_http_lua_run_thread(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, volatile int nrets)
{
    ngx_http_lua_co_ctx_t   *next_coctx, *parent_coctx, *orig_coctx;
    int                      rv, success = 1;
    lua_State               *next_co;
    lua_State               *old_co;
    const char              *err, *msg, *trace;
    ngx_int_t                rc;
#if (NGX_PCRE)
    ngx_pool_t              *old_pool = NULL;
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread, top:%d c:%ud", lua_gettop(L),
                   r->main->count);

    /* set Lua VM panic handler */
    /* 参考Lua5.1参考手册，lua_atpanic()
       If an error happens outside any protected environment, Lua calls a 
       panic function and then calls exit(EXIT_FAILURE), thus exiting the 
       host application. Your panic function can avoid this exit by never 
       returning (e.g., doing a long jump). 
       
       注册新的panic处理函数，以防止执行exit()使得worker进程退出；可以通过
       long jmp，跳转到最近的代码点

       <TAKE CARE!!!>就是通过此手段，即便Lua脚本崩溃了，也不会影响nginx的
                     正常流程，牛逼阿!!!  */
    lua_atpanic(L, ngx_http_lua_atpanic);

    dd("ctx = %p", ctx);

    /* 利用longjmp实现的try-catch，以防止Lua脚本崩溃导致worker异常退出 */
    NGX_LUA_EXCEPTION_TRY {

        if (ctx->cur_co_ctx->thread_spawn_yielded) {
            ngx_http_lua_probe_info("thread spawn yielded");

            ctx->cur_co_ctx->thread_spawn_yielded = 0;
            nrets = 1;
        }

        /* 线程主循环 */
        for ( ;; ) {

            dd("calling lua_resume: vm %p, nret %d", ctx->cur_co_ctx->co,
               (int) nrets);

#if (NGX_PCRE)
            /* XXX: work-around to nginx regex subsystem */
            old_pool = ngx_http_lua_pcre_malloc_init(r->pool);
#endif

            /*  run code */
            dd("ctx: %p", ctx);
            dd("cur co: %p", ctx->cur_co_ctx->co);
            dd("cur co status: %d", ctx->cur_co_ctx->co_status);

            orig_coctx = ctx->cur_co_ctx;

#ifdef NGX_LUA_USE_ASSERT
            dd("%p: saved co top: %d, nrets: %d, true top: %d",
               orig_coctx->co,
               (int) orig_coctx->co_top, (int) nrets,
               (int) lua_gettop(orig_coctx->co));
#endif

#if DDEBUG
            if (lua_gettop(orig_coctx->co) > 0) {
                dd("top elem: %s", luaL_typename(orig_coctx->co, -1));
            }
#endif
            /* 检查堆栈栈顶，和resume前是否一致 */
            ngx_http_lua_assert(orig_coctx->co_top + nrets
                                == lua_gettop(orig_coctx->co));

            /* 协程的resume，恢复运行；
                  返回值为0, 表示执行完毕
                  返回值为LUA_YIELD，表示主动让出执行权限
               无论何种情况，栈中都会压入返回结果或lua_yield的入参 */
            rv = lua_resume(orig_coctx->co, nrets);

#if (NGX_PCRE)
            /* XXX: work-around to nginx regex subsystem */
            ngx_http_lua_pcre_malloc_done(old_pool);
#endif

#if 0
            /* test the longjmp thing */
            if (rand() % 2 == 0) {
                NGX_LUA_EXCEPTION_THROW(1);
            }
#endif

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua resume returned %d", rv);

            /* 返回值处理，分两大类，0或者LUA_YIELD;
               1) 对于LUA_YIELD，表征资源不到位或遇到了阻塞性操作，主动
                  让出CPU，后续利用事件驱动的方式通知并重启此协程
               2) 对于0, 表示处理结束 */
            switch (rv) {
            /*** 遇到阻塞事件 ***/                
            case LUA_YIELD:          
                /*  yielded, let event handler do the rest job */
                /*  FIXME: add io cmd dispatcher here */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "lua thread yielded");

#ifdef NGX_LUA_USE_ASSERT
                dd("%p: saving curr top after yield: %d (co-op: %d)",
                   orig_coctx->co,
                   (int) lua_gettop(orig_coctx->co), (int) ctx->co_op);
                orig_coctx->co_top = lua_gettop(orig_coctx->co);
#endif

                if (r->uri_changed) {
                    return ngx_http_lua_handle_rewrite_jump(L, r, ctx);
                }

                if (ctx->exited) {
                    return ngx_http_lua_handle_exit(L, r, ctx);
                }

                if (ctx->exec_uri.len) {
                    return ngx_http_lua_handle_exec(L, r, ctx);
                }

                /*
                 * check if coroutine.resume or coroutine.yield called
                 * lua_yield()
                 */
                switch(ctx->co_op) {
                case NGX_HTTP_LUA_USER_CORO_NOP:
                    dd("hit! it is the API yield");

                    ngx_http_lua_assert(lua_gettop(ctx->cur_co_ctx->co) == 0);

                    ctx->cur_co_ctx = NULL;

                    return NGX_AGAIN;

                case NGX_HTTP_LUA_USER_THREAD_RESUME:

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "lua user thread resume");

                    ctx->co_op = NGX_HTTP_LUA_USER_CORO_NOP;
                    nrets = lua_gettop(ctx->cur_co_ctx->co) - 1;
                    dd("nrets = %d", nrets);

#ifdef NGX_LUA_USE_ASSERT
                    /* ignore the return value (the thread) already pushed */
                    orig_coctx->co_top--;
#endif

                    break;

                case NGX_HTTP_LUA_USER_CORO_RESUME:
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "lua coroutine: resume");

                    /*
                     * the target coroutine lies at the base of the
                     * parent's stack
                     */
                    ctx->co_op = NGX_HTTP_LUA_USER_CORO_NOP;

                    old_co = ctx->cur_co_ctx->parent_co_ctx->co;

                    nrets = lua_gettop(old_co);
                    if (nrets) {
                        dd("moving %d return values to parent", nrets);
                        lua_xmove(old_co, ctx->cur_co_ctx->co, nrets);

#ifdef NGX_LUA_USE_ASSERT
                        ctx->cur_co_ctx->parent_co_ctx->co_top -= nrets;
#endif
                    }

                    break;

                default:
                    /* ctx->co_op == NGX_HTTP_LUA_USER_CORO_YIELD */

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "lua coroutine: yield");

                    ctx->co_op = NGX_HTTP_LUA_USER_CORO_NOP;

                    if (ngx_http_lua_is_thread(ctx)) {
                        ngx_http_lua_probe_thread_yield(r, ctx->cur_co_ctx->co);

                        /* discard any return values from user
                         * coroutine.yield()'s arguments */
                        lua_settop(ctx->cur_co_ctx->co, 0);

#ifdef NGX_LUA_USE_ASSERT
                        ctx->cur_co_ctx->co_top = 0;
#endif

                        ngx_http_lua_probe_info("set co running");
                        ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

                        if (ctx->posted_threads) {
                            ngx_http_lua_post_thread(r, ctx, ctx->cur_co_ctx);
                            ctx->cur_co_ctx = NULL;
                            return NGX_AGAIN;
                        }

                        /* no pending threads, so resume the thread
                         * immediately */

                        nrets = 0;
                        continue;
                    }

                    /* being a user coroutine that has a parent */

                    nrets = lua_gettop(ctx->cur_co_ctx->co);

                    next_coctx = ctx->cur_co_ctx->parent_co_ctx;
                    next_co = next_coctx->co;

                    /*
                     * prepare return values for coroutine.resume
                     * (true plus any retvals)
                     */
                    lua_pushboolean(next_co, 1);

                    if (nrets) {
                        dd("moving %d return values to next co", nrets);
                        lua_xmove(ctx->cur_co_ctx->co, next_co, nrets);
#ifdef NGX_LUA_USE_ASSERT
                        ctx->cur_co_ctx->co_top -= nrets;
#endif
                    }

                    nrets++;  /* add the true boolean value */

                    ctx->cur_co_ctx = next_coctx;

                    break;
                }

                /* try resuming on the new coroutine again */
                continue;
                
            /*** 执行完毕 ***/
            case 0:

                ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);
                ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

                /* 设置协程状态，ngx_http_lua_co_status_t，表示已完成任务 */
                ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

                /* 清理僵尸子协程 */
                if (ctx->cur_co_ctx->zombie_child_threads) {
                    ngx_http_lua_cleanup_zombie_child_uthreads(r, L, ctx,
                                                               ctx->cur_co_ctx);
                }

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "lua light thread ended normally");

                /* 角色主协程，即入口协程，从全局注册表清理 */
                if (ngx_http_lua_is_entry_thread(ctx)) {
                    lua_settop(L, 0);

                    ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx); /* 清理全局注册表 */

                    dd("uthreads: %d", (int) ctx->uthreads);
                    if (ctx->uthreads) {                                 /* 尚有活跃的子协程 */
                        ctx->cur_co_ctx = NULL;
                        return NGX_AGAIN;
                    }

                    /* all user threads terminated already */
                    goto done;
                }
                
                /* 角色子协程，即cosocket对应的协程 */
                if (ctx->cur_co_ctx->is_uthread) {
                    /* being a user thread */
                    lua_settop(L, 0);

                    parent_coctx = ctx->cur_co_ctx->parent_co_ctx;
                    /* 父协程存活 */
                    if (ngx_http_lua_coroutine_alive(parent_coctx)) {
                        if (ctx->cur_co_ctx->waited_by_parent) {
                            ngx_http_lua_probe_info("parent already waiting");
                            ctx->cur_co_ctx->waited_by_parent = 0;
                            success = 1;      /* 类似于wait() */
                            goto user_co_done;
                        }

                        ngx_http_lua_probe_info("parent still alive");
                        if (ngx_http_lua_post_zombie_thread(r, parent_coctx,
                                                            ctx->cur_co_ctx)
                            != NGX_OK)        /* 加入父协程的->zombie_child_threads 链表 */
                        {
                            return NGX_ERROR;
                        }
                                              /* 压栈返回值，待父协程处理 */
                        lua_pushboolean(ctx->cur_co_ctx->co, 1);
                        lua_insert(ctx->cur_co_ctx->co, 1);   /* 压栈的bool值移动到索引为1处 */
                                              /* 设置为僵尸子协程 */
                        ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_ZOMBIE;
                        ctx->cur_co_ctx = NULL;
                        return NGX_AGAIN;
                    }
                    /* 父协程未存活，提前结束任务 */
                    ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                    ctx->uthreads--;          /* 减少活跃子协程数 */

                    if (ctx->uthreads == 0) {
                        if (ngx_http_lua_entry_thread_alive(ctx)) {
                            ctx->cur_co_ctx = NULL;
                            return NGX_AGAIN;
                        }

                        /* all threads terminated already */
                        goto done;
                    }

                    /* some other user threads still running */
                    ctx->cur_co_ctx = NULL;
                    return NGX_AGAIN;
                }

                /* being a user coroutine that has a parent */
                success = 1;

user_co_done:
                nrets = lua_gettop(ctx->cur_co_ctx->co);

                next_coctx = ctx->cur_co_ctx->parent_co_ctx;

                if (next_coctx == NULL) {
                    /* being a light thread */
                    goto no_parent;
                }

                next_co = next_coctx->co;

                /*
                 * ended successful, coroutine.resume returns true plus
                 * any return values
                 */
                /* 子协程的返回值压入父协程栈 */
                lua_pushboolean(next_co, success);
                if (nrets) {
                    lua_xmove(ctx->cur_co_ctx->co, next_co, nrets);
                }

                if (ctx->cur_co_ctx->is_uthread) {
                    ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                    ctx->uthreads--;
                }

                /* 指向父协程 */
                nrets++;
                ctx->cur_co_ctx = next_coctx;

                ngx_http_lua_probe_info("set parent running");

                /* 设置父协程运行 */
                next_coctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "lua coroutine: lua user thread ended normally");
                continue;
            /*** 其他错误 ***/
            case LUA_ERRRUN:
                err = "runtime error";
                break;

            case LUA_ERRSYNTAX:
                err = "syntax error";
                break;

            case LUA_ERRMEM:
                err = "memory allocation error";
                ngx_quit = 1;
                break;

            case LUA_ERRERR:
                err = "error handler error";
                break;

            default:
                err = "unknown error";
                break;
            }

            if (ctx->cur_co_ctx != orig_coctx) {
                ctx->cur_co_ctx = orig_coctx;
            }

            if (lua_isstring(ctx->cur_co_ctx->co, -1)) {
                dd("user custom error msg");
                msg = lua_tostring(ctx->cur_co_ctx->co, -1);

            } else {
                msg = "unknown reason";
            }

            ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);
            ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 0);

            ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

            ngx_http_lua_thread_traceback(L, ctx->cur_co_ctx->co,
                                          ctx->cur_co_ctx);
            trace = lua_tostring(L, -1);

            if (ctx->cur_co_ctx->is_uthread) {

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "lua user thread aborted: %s: %s\n%s",
                              err, msg, trace);

                lua_settop(L, 0);

                parent_coctx = ctx->cur_co_ctx->parent_co_ctx;

                if (ngx_http_lua_coroutine_alive(parent_coctx)) {
                    if (ctx->cur_co_ctx->waited_by_parent) {
                        ctx->cur_co_ctx->waited_by_parent = 0;
                        success = 0;
                        goto user_co_done;
                    }

                    if (ngx_http_lua_post_zombie_thread(r, parent_coctx,
                                                        ctx->cur_co_ctx)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    lua_pushboolean(ctx->cur_co_ctx->co, 0);
                    lua_insert(ctx->cur_co_ctx->co, 1);

                    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_ZOMBIE;
                    ctx->cur_co_ctx = NULL;
                    return NGX_AGAIN;
                }

                ngx_http_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                ctx->uthreads--;

                if (ctx->uthreads == 0) {
                    if (ngx_http_lua_entry_thread_alive(ctx)) {
                        ctx->cur_co_ctx = NULL;
                        return NGX_AGAIN;
                    }

                    /* all threads terminated already */
                    goto done;
                }

                /* some other user threads still running */
                ctx->cur_co_ctx = NULL;
                return NGX_AGAIN;
            }

            if (ngx_http_lua_is_entry_thread(ctx)) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "lua entry thread aborted: %s: %s\n%s",
                              err, msg, trace);

                lua_settop(L, 0);

                /* being the entry thread aborted */

                if (r->filter_finalize) {
                    ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
                }

                ngx_http_lua_request_cleanup(ctx, 0);

                dd("headers sent? %d", r->header_sent || ctx->header_sent);

                if (ctx->no_abort) {
                    ctx->no_abort = 0;
                    return NGX_ERROR;
                }

                return (r->header_sent || ctx->header_sent) ? NGX_ERROR :
                       NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* being a user coroutine that has a parent */

            next_coctx = ctx->cur_co_ctx->parent_co_ctx;
            if (next_coctx == NULL) {
                goto no_parent;
            }

            next_co = next_coctx->co;

            ngx_http_lua_probe_info("set parent running");

            next_coctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

            /*
             * ended with error, coroutine.resume returns false plus
             * err msg
             */
            lua_pushboolean(next_co, 0);
            lua_xmove(ctx->cur_co_ctx->co, next_co, 1);
            nrets = 2;

            ctx->cur_co_ctx = next_coctx;

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "lua coroutine: %s: %s\n%s", err, msg, trace);

            /* try resuming on the new coroutine again */
            continue;
        }
    }
    /* <TAKECARE!!!>发生panic后，跳转至此，仅仅打印日志，然后退出 */
    NGX_LUA_EXCEPTION_CATCH {
        dd("nginx execution restored");
    }

    return NGX_ERROR;

no_parent:

    lua_settop(L, 0);

    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 0);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "lua handler aborted: "
                  "user coroutine has no parent");

    return (r->header_sent || ctx->header_sent) ?
                NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR;

done:

    /* 内容处理完毕，调用发送函数 */
    if (ctx->entered_content_phase
        && r->connection->fd != (ngx_socket_t) -1)
    {
        rc = ngx_http_lua_send_chain_link(r, ctx,
                                          NULL /* last_buf */);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_lua_wev_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_event_t                 *wev;
    ngx_connection_t            *c;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_core_loc_conf_t    *clcf;

    ngx_http_lua_socket_tcp_upstream_t *u;

    c = r->connection;
    wev = c->write;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "lua run write event handler: timedout:%ud, ready:%ud, "
                   "writing_raw_req_socket:%ud",
                   wev->timedout, wev->ready, ctx->writing_raw_req_socket);

    clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

    if (wev->timedout && !ctx->writing_raw_req_socket) {
        if (!wev->delayed) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

            goto flush_coros;
        }

        wev->timedout = 0;
        wev->delayed = 0;

        if (!wev->ready) {
            ngx_add_timer(wev, clcf->send_timeout);

            if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
                if (ctx->entered_content_phase) {
                    ngx_http_lua_finalize_request(r, NGX_ERROR);
                }
                return NGX_ERROR;
            }
        }
    }

    if (!wev->ready && !wev->timedout) {
        goto useless;
    }

    if (ctx->writing_raw_req_socket) {
        ctx->writing_raw_req_socket = 0;

        u = ctx->downstream;
        if (u == NULL) {
            return NGX_ERROR;
        }

        u->write_event_handler(r, u);
        return NGX_DONE;
    }

    if (c->buffered & NGX_HTTP_LOWLEVEL_BUFFERED) {
        rc = ngx_http_lua_flush_pending_output(r, ctx);

        dd("flush pending output returned %d, c->error: %d", (int) rc,
           c->error);

        if (rc != NGX_ERROR && rc != NGX_OK) {
            goto useless;
        }

        /* when rc == NGX_ERROR, c->error must be set */
    }

flush_coros:

    dd("ctx->flushing_coros: %d", (int) ctx->flushing_coros);

    if (ctx->flushing_coros) {
        return ngx_http_lua_process_flushing_coroutines(r, ctx);
    }

    /* ctx->flushing_coros == 0 */

useless:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "useless lua write event handler");

    if (ctx->entered_content_phase) {
        return NGX_OK;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_lua_process_flushing_coroutines(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t                    rc, n;
    ngx_uint_t                   i;
    ngx_list_part_t             *part;
    ngx_http_lua_co_ctx_t       *coctx;

    dd("processing flushing coroutines");

    coctx = &ctx->entry_co_ctx;
    n = ctx->flushing_coros;

    if (coctx->flushing) {
        coctx->flushing = 0;

        ctx->flushing_coros--;
        n--;
        ctx->cur_co_ctx = coctx;

        rc = ngx_http_lua_flush_resume_helper(r, ctx);
        if (rc == NGX_ERROR || rc >= NGX_OK) {
            return rc;
        }

        /* rc == NGX_DONE */
    }

    if (n) {

        if (ctx->user_co_ctx == NULL) {
            return NGX_ERROR;
        }

        part = &ctx->user_co_ctx->part;
        coctx = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                coctx = part->elts;
                i = 0;
            }

            if (coctx[i].flushing) {
                coctx[i].flushing = 0;
                ctx->flushing_coros--;
                n--;
                ctx->cur_co_ctx = &coctx[i];

                rc = ngx_http_lua_flush_resume_helper(r, ctx);
                if (rc == NGX_ERROR || rc >= NGX_OK) {
                    return rc;
                }

                /* rc == NGX_DONE */

                if (n == 0) {
                    return NGX_DONE;
                }
            }
        }
    }

    if (n) {
        return NGX_ERROR;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_lua_flush_pending_output(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t           rc;
    ngx_chain_t        *cl;
    ngx_event_t        *wev;
    ngx_connection_t   *c;

    ngx_http_core_loc_conf_t    *clcf;

    c = r->connection;
    wev = c->write;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "lua flushing output: buffered 0x%uxd",
                   c->buffered);

    if (ctx->busy_bufs) {
        /* FIXME since cosockets also share this busy_bufs chain, this condition
         * might not be strong enough. better use separate busy_bufs chains. */
        rc = ngx_http_lua_output_filter(r, NULL);

    } else {
        cl = ngx_http_lua_get_flush_chain(r, ctx);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_http_lua_output_filter(r, cl);
    }

    dd("output filter returned %d", (int) rc);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (c->buffered & NGX_HTTP_LOWLEVEL_BUFFERED) {

        clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            if (ctx->entered_content_phase) {
                ngx_http_lua_finalize_request(r, NGX_ERROR);
            }

            return NGX_ERROR;
        }

        if (ctx->flushing_coros) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "lua flush still waiting: buffered 0x%uxd",
                           c->buffered);

            return NGX_DONE;
        }

    } else {
#if 1
        if (wev->timer_set && !wev->delayed) {
            ngx_del_timer(wev);
        }
#endif
    }

    return NGX_OK;
}


u_char *
ngx_http_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len)
{
    ngx_md5_t                     md5;
    u_char                        md5_buf[MD5_DIGEST_LENGTH];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, buf, buf_len);
    ngx_md5_final(md5_buf, &md5);

    return ngx_hex_dump(dest, md5_buf, sizeof(md5_buf));
}


void
ngx_http_lua_set_multi_value_table(lua_State *L, int index)
{
    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    lua_pushvalue(L, -2); /* stack: table key value key */
    lua_rawget(L, index);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1); /* stack: table key value */
        lua_rawset(L, index); /* stack: table */

    } else {
        if (!lua_istable(L, -1)) {
            /* just inserted one value */
            lua_createtable(L, 4, 0);
                /* stack: table key value value table */
            lua_insert(L, -2);
                /* stack: table key value table value */
            lua_rawseti(L, -2, 1);
                /* stack: table key value table */
            lua_insert(L, -2);
                /* stack: table key table value */

            lua_rawseti(L, -2, 2); /* stack: table key table */

            lua_rawset(L, index); /* stack: table */

        } else {
            /* stack: table key value table */
            lua_insert(L, -2); /* stack: table key table value */

            lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
                /* stack: table key table  */
            lua_pop(L, 2); /* stack: table */
        }
    }
}


uintptr_t
ngx_http_lua_escape_uri(u_char *dst, u_char *src, size_t size, ngx_uint_t type)
{
    ngx_uint_t      n;
    uint32_t       *escape;
    static u_char   hex[] = "0123456789ABCDEF";

                    /* " ", "#", "%", "?", %00-%1F, %7F-%FF */

    static uint32_t   uri[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0xfc00886d, /* 1111 1100 0000 0000  1000 1000 0110 1101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x78000000, /* 0111 1000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0xa8000000, /* 1010 1000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "#", "%", "+", "?", %00-%1F, %7F-%FF */

    static uint32_t   args[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x80000829, /* 1000 0000 0000 0000  0000 1000 0010 1001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "#", """, "%", "'", %00-%1F, %7F-%FF */

    static uint32_t   html[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x000000ad, /* 0000 0000 0000 0000  0000 0000 1010 1101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", """, "%", "'", %00-%1F, %7F-%FF */

    static uint32_t   refresh[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000085, /* 0000 0000 0000 0000  0000 0000 1000 0101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "%", %00-%1F */

    static uint32_t   memcached[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000021, /* 0000 0000 0000 0000  0000 0000 0010 0001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    };

                    /* mail_auth is the same as memcached */

    static uint32_t  *map[] =
        { uri, args, html, refresh, memcached, memcached };


    escape = map[type];

    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
            *dst++ = '%';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}


/* XXX we also decode '+' to ' ' */
void
ngx_http_lua_unescape_uri(u_char **dst, u_char **src, size_t size,
    ngx_uint_t type)
{
    u_char  *d, *s, ch, c, decoded;
    enum {
        sw_usual = 0,
        sw_quoted,
        sw_quoted_second
    } state;

    d = *dst;
    s = *src;

    state = 0;
    decoded = 0;

    while (size--) {

        ch = *s++;

        switch (state) {
        case sw_usual:
            if (ch == '?'
                && (type & (NGX_UNESCAPE_URI|NGX_UNESCAPE_REDIRECT)))
            {
                *d++ = ch;
                goto done;
            }

            if (ch == '%') {
                state = sw_quoted;
                break;
            }

            if (ch == '+') {
                *d++ = ' ';
                break;
            }

            *d++ = ch;
            break;

        case sw_quoted:

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                break;
            }

            /* the invalid quoted character */

            state = sw_usual;

            *d++ = ch;

            break;

        case sw_quoted_second:

            state = sw_usual;

            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                if (type & NGX_UNESCAPE_URI) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }

            /* the invalid quoted character */

            break;
        }
    }

done:

    *dst = d;
    *src = s;
}


void
ngx_http_lua_inject_req_api(ngx_log_t *log, lua_State *L)
{
    /* ngx.req table */

    lua_createtable(L, 0 /* narr */, 24 /* nrec */);    /* .req */

    ngx_http_lua_inject_req_header_api(L);
    ngx_http_lua_inject_req_uri_api(log, L);
    ngx_http_lua_inject_req_args_api(L);
    ngx_http_lua_inject_req_body_api(L);
    ngx_http_lua_inject_req_socket_api(L);
    ngx_http_lua_inject_req_method_api(L);
    ngx_http_lua_inject_req_time_api(L);
    ngx_http_lua_inject_req_misc_api(L);

    lua_setfield(L, -2, "req");
}


static ngx_int_t
ngx_http_lua_handle_exec(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t               rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua thread initiated internal redirect to %V",
                   &ctx->exec_uri);

    ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

    ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 1 /* forcible */);

    if (ctx->exec_uri.data[0] == '@') {
        if (ctx->exec_args.len > 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "query strings %V ignored when exec'ing "
                          "named location %V",
                          &ctx->exec_args, &ctx->exec_uri);
        }

        r->write_event_handler = ngx_http_request_empty_handler;

#if 1
        if (r->read_event_handler == ngx_http_lua_rd_check_broken_connection) {
            /* resume the read event handler */

            r->read_event_handler = ngx_http_block_reading;
        }
#endif

#if 1
        /* clear the modules contexts */
        ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);
#endif

        rc = ngx_http_named_location(r, &ctx->exec_uri);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE)
        {
            return rc;
        }

#if 0
        if (!ctx->entered_content_phase) {
            /* XXX ensure the main request ref count
             * is decreased because the current
             * request will be quit */
            r->main->count--;
            dd("XXX decrement main count: c:%d", (int) r->main->count);
        }
#endif

        return NGX_DONE;
    }

    dd("internal redirect to %.*s", (int) ctx->exec_uri.len,
       ctx->exec_uri.data);

    r->write_event_handler = ngx_http_request_empty_handler;

    if (r->read_event_handler == ngx_http_lua_rd_check_broken_connection) {
        /* resume the read event handler */

        r->read_event_handler = ngx_http_block_reading;
    }

    rc = ngx_http_internal_redirect(r, &ctx->exec_uri, &ctx->exec_args);

    dd("internal redirect returned %d when in content phase? "
       "%d", (int) rc, ctx->entered_content_phase);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

#if 0
    if (!ctx->entered_content_phase) {
        /* XXX ensure the main request ref count
         * is decreased because the current
         * request will be quit */
        dd("XXX decrement main count");
        r->main->count--;
    }
#endif

    return NGX_DONE;
}


static ngx_int_t
ngx_http_lua_handle_exit(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t           rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua thread aborting request with status %d",
                   ctx->exit_code);

    ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

    ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 0);

    if (r->connection->fd == (ngx_socket_t) -1) {  /* fake request */
        return ctx->exit_code;
    }

#if 1
    if (!r->header_sent
        && !ctx->header_sent
        && r->headers_out.status == 0
        && ctx->exit_code >= NGX_HTTP_OK)
    {
        r->headers_out.status = ctx->exit_code;
    }
#endif

    if (ctx->buffering
        && r->headers_out.status
        && ctx->exit_code != NGX_ERROR
        && ctx->exit_code != NGX_HTTP_REQUEST_TIME_OUT
        && ctx->exit_code != NGX_HTTP_CLIENT_CLOSED_REQUEST
        && ctx->exit_code != NGX_HTTP_CLOSE)
    {
        rc = ngx_http_lua_send_chain_link(r, ctx, NULL /* indicate last_buf */);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (ctx->exit_code >= NGX_HTTP_OK) {
            return NGX_HTTP_OK;
        }

        return ctx->exit_code;
    }

    if ((ctx->exit_code == NGX_OK
         && ctx->entered_content_phase)
        || (ctx->exit_code >= NGX_HTTP_OK
            && ctx->exit_code < NGX_HTTP_SPECIAL_RESPONSE
            && ctx->exit_code != NGX_HTTP_NO_CONTENT))
    {
        rc = ngx_http_lua_send_chain_link(r, ctx, NULL /* indicate last_buf */);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

#if 1
    if ((r->header_sent || ctx->header_sent)
        && ctx->exit_code > NGX_OK
        && ctx->exit_code != NGX_HTTP_REQUEST_TIME_OUT
        && ctx->exit_code != NGX_HTTP_CLIENT_CLOSED_REQUEST
        && ctx->exit_code != NGX_HTTP_CLOSE)
    {
        if (ctx->entered_content_phase) {
            return NGX_OK;
        }

        return NGX_HTTP_OK;
    }
#endif

    return ctx->exit_code;
}


void
ngx_http_lua_process_args_option(ngx_http_request_t *r, lua_State *L,
    int table, ngx_str_t *args)
{
    u_char              *key;
    size_t               key_len;
    u_char              *value;
    size_t               value_len;
    size_t               len = 0;
    size_t               key_escape = 0;
    uintptr_t            total_escape = 0;
    int                  n;
    int                  i;
    u_char              *p;

    if (table < 0) {
        table = lua_gettop(L) + table + 1;
    }

    n = 0;
    lua_pushnil(L);
    while (lua_next(L, table) != 0) {
        if (lua_type(L, -2) != LUA_TSTRING) {
            luaL_error(L, "attempt to use a non-string key in the "
                       "\"args\" option table");
            return;
        }

        key = (u_char *) lua_tolstring(L, -2, &key_len);

        key_escape = 2 * ngx_http_lua_escape_uri(NULL, key, key_len,
                                                 NGX_ESCAPE_URI);
        total_escape += key_escape;

        switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            value = (u_char *) lua_tolstring(L, -1, &value_len);

            total_escape += 2 * ngx_http_lua_escape_uri(NULL, value, value_len,
                                                        NGX_ESCAPE_URI);

            len += key_len + value_len + (sizeof("=") - 1);
            n++;

            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, -1)) {
                len += key_len;
                n++;
            }

            break;

        case LUA_TTABLE:

            i = 0;
            lua_pushnil(L);
            while (lua_next(L, -2) != 0) {
                if (lua_isboolean(L, -1)) {
                    if (lua_toboolean(L, -1)) {
                        len += key_len;

                    } else {
                        lua_pop(L, 1);
                        continue;
                    }

                } else {
                    value = (u_char *) lua_tolstring(L, -1, &value_len);

                    if (value == NULL) {
                        luaL_error(L, "attempt to use %s as query arg value",
                                   luaL_typename(L, -1));
                        return;
                    }

                    total_escape +=
                        2 * ngx_http_lua_escape_uri(NULL, value,
                                                    value_len,
                                                    NGX_ESCAPE_URI);

                    len += key_len + value_len + (sizeof("=") - 1);
                }

                if (i++ > 0) {
                    total_escape += key_escape;
                }

                n++;
                lua_pop(L, 1);
            }

            break;

        default:
            luaL_error(L, "attempt to use %s as query arg value",
                       luaL_typename(L, -1));
            return;
        }

        lua_pop(L, 1);
    }

    len += (size_t) total_escape;

    if (n > 1) {
        len += (n - 1) * (sizeof("&") - 1);
    }

    dd("len 1: %d", (int) len);

    if (r) {
        p = ngx_palloc(r->pool, len);
        if (p == NULL) {
            luaL_error(L, "no memory");
            return;
        }

    } else {
        p = lua_newuserdata(L, len);
    }

    args->data = p;
    args->len = len;

    i = 0;
    lua_pushnil(L);
    while (lua_next(L, table) != 0) {
        key = (u_char *) lua_tolstring(L, -2, &key_len);

        switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:

            if (total_escape) {
                p = (u_char *) ngx_http_lua_escape_uri(p, key, key_len,
                                                       NGX_ESCAPE_URI);

            } else {
                dd("shortcut: no escape required");

                p = ngx_copy(p, key, key_len);
            }

            *p++ = '=';

            value = (u_char *) lua_tolstring(L, -1, &value_len);

            if (total_escape) {
                p = (u_char *) ngx_http_lua_escape_uri(p, value, value_len,
                                                       NGX_ESCAPE_URI);

            } else {
                p = ngx_copy(p, value, value_len);
            }

            if (i != n - 1) {
                /* not the last pair */
                *p++ = '&';
            }

            i++;

            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, -1)) {
                if (total_escape) {
                    p = (u_char *) ngx_http_lua_escape_uri(p, key, key_len,
                                                           NGX_ESCAPE_URI);

                } else {
                    dd("shortcut: no escape required");

                    p = ngx_copy(p, key, key_len);
                }

                if (i != n - 1) {
                    /* not the last pair */
                    *p++ = '&';
                }

                i++;
            }

            break;

        case LUA_TTABLE:

            lua_pushnil(L);
            while (lua_next(L, -2) != 0) {

                if (lua_isboolean(L, -1)) {
                    if (lua_toboolean(L, -1)) {
                        if (total_escape) {
                            p = (u_char *) ngx_http_lua_escape_uri(p, key,
    key_len,
    NGX_ESCAPE_URI);

                        } else {
                            dd("shortcut: no escape required");

                            p = ngx_copy(p, key, key_len);
                        }

                    } else {
                        lua_pop(L, 1);
                        continue;
                    }

                } else {

                    if (total_escape) {
                        p = (u_char *)
                                ngx_http_lua_escape_uri(p, key,
                                                        key_len,
                                                        NGX_ESCAPE_URI);

                    } else {
                        dd("shortcut: no escape required");

                        p = ngx_copy(p, key, key_len);
                    }

                    *p++ = '=';

                    value = (u_char *) lua_tolstring(L, -1, &value_len);

                    if (total_escape) {
                        p = (u_char *)
                                ngx_http_lua_escape_uri(p, value,
                                                        value_len,
                                                        NGX_ESCAPE_URI);

                    } else {
                        p = ngx_copy(p, value, value_len);
                    }
                }

                if (i != n - 1) {
                    /* not the last pair */
                    *p++ = '&';
                }

                i++;
                lua_pop(L, 1);
            }

            break;

        default:
            luaL_error(L, "should not reach here");
            return;
        }

        lua_pop(L, 1);
    }

    if (p - args->data != (ssize_t) len) {
        luaL_error(L, "buffer error: %d != %d",
                   (int) (p - args->data), (int) len);
        return;
    }
}


static ngx_int_t
ngx_http_lua_handle_rewrite_jump(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua thread aborting request with URI rewrite jump: "
                   "\"%V?%V\"", &r->uri, &r->args);

    ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);

    ngx_http_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_DEAD;

    if (r->filter_finalize) {
        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    ngx_http_lua_request_cleanup(ctx, 1 /* forcible */);
    ngx_http_lua_init_ctx(r, ctx);

    return NGX_OK;
}


/* XXX ngx_open_and_stat_file is static in the core. sigh. */
ngx_int_t
ngx_http_lua_open_and_stat_file(u_char *name, ngx_open_file_info_t *of,
    ngx_log_t *log)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;

    if (of->fd != NGX_INVALID_FILE) {

        if (ngx_file_info(name, &fi) == NGX_FILE_ERROR) {
            of->failed = ngx_file_info_n;
            goto failed;
        }

        if (of->uniq == ngx_file_uniq(&fi)) {
            goto done;
        }

    } else if (of->test_dir) {

        if (ngx_file_info(name, &fi) == NGX_FILE_ERROR) {
            of->failed = ngx_file_info_n;
            goto failed;
        }

        if (ngx_is_dir(&fi)) {
            goto done;
        }
    }

    if (!of->log) {

        /*
         * Use non-blocking open() not to hang on FIFO files, etc.
         * This flag has no effect on a regular files.
         */

        fd = ngx_open_file(name, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
                           NGX_FILE_OPEN, 0);

    } else {
        fd = ngx_open_file(name, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN,
                           NGX_FILE_DEFAULT_ACCESS);
    }

    if (fd == NGX_INVALID_FILE) {
        of->failed = ngx_open_file_n;
        goto failed;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", name);

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name);
        }

        of->fd = NGX_INVALID_FILE;

        return NGX_ERROR;
    }

    if (ngx_is_dir(&fi)) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name);
        }

        of->fd = NGX_INVALID_FILE;

    } else {
        of->fd = fd;

        if (of->directio <= ngx_file_size(&fi)) {
            if (ngx_directio_on(fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                              ngx_directio_on_n " \"%s\" failed", name);

            } else {
                of->is_directio = 1;
            }
        }
    }

done:

    of->uniq = ngx_file_uniq(&fi);
    of->mtime = ngx_file_mtime(&fi);
    of->size = ngx_file_size(&fi);
#if defined(nginx_version) && nginx_version >= 1000001
    of->fs_size = ngx_file_fs_size(&fi);
#endif
    of->is_dir = ngx_is_dir(&fi);
    of->is_file = ngx_is_file(&fi);
    of->is_link = ngx_is_link(&fi);
    of->is_exec = ngx_is_exec(&fi);

    return NGX_OK;

failed:

    of->fd = NGX_INVALID_FILE;
    of->err = ngx_errno;

    return NGX_ERROR;
}


ngx_chain_t *
ngx_http_lua_chain_get_free_buf(ngx_log_t *log, ngx_pool_t *p,
    ngx_chain_t **free, size_t len)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    u_char       *start, *end;

    const ngx_buf_tag_t  tag = (ngx_buf_tag_t) &ngx_http_lua_module;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;

        b = cl->buf;
        start = b->start;
        end = b->end;
        if (start && (size_t) (end - start) >= len) {
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "lua reuse free buf memory %O >= %uz, cl:%p, p:%p",
                           (off_t) (end - start), len, cl, start);

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->start = start;
            b->pos = start;
            b->last = start;
            b->end = end;
            b->tag = tag;

            if (len) {
                b->temporary = 1;
            }

            return cl;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                       "lua reuse free buf chain, but reallocate memory "
                       "because %uz >= %O, cl:%p, p:%p", len,
                       (off_t) (b->end - b->start), cl, b->start);

        if (ngx_buf_in_memory(b) && b->start) {
            ngx_pfree(p, b->start);
        }

        ngx_memzero(b, sizeof(ngx_buf_t));

        if (len == 0) {
            return cl;
        }

        b->start = ngx_palloc(p, len);
        if (b->start == NULL) {
            return NULL;
        }

        b->end = b->start + len;

        dd("buf start: %p", cl->buf->start);

        b->pos = b->start;
        b->last = b->start;
        b->tag = tag;
        b->temporary = 1;

        return cl;
    }

    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua allocate new chainlink and new buf of size %uz, cl:%p",
                   len, cl);

    cl->buf = len ? ngx_create_temp_buf(p, len) : ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    dd("buf start: %p", cl->buf->start);

    cl->buf->tag = tag;
    cl->next = NULL;

    return cl;
}


static int
ngx_http_lua_thread_traceback(lua_State *L, lua_State *co,
    ngx_http_lua_co_ctx_t *coctx)
{
    int         base;
    int         level, coid;
    lua_Debug   ar;

    base = lua_gettop(L);
    lua_checkstack(L, 3);
    lua_pushliteral(L, "stack traceback:");
    coid = 0;

    while (co) {

        if (coid >= NGX_HTTP_LUA_BT_MAX_COROS) {
            break;
        }

        lua_checkstack(L, 2);
        lua_pushfstring(L, "\ncoroutine %d:", coid++);

        level = 0;

        while (lua_getstack(co, level++, &ar)) {

            lua_checkstack(L, 5);

            if (level > NGX_HTTP_LUA_BT_DEPTH) {
                lua_pushliteral(L, "\n\t...");
                break;
            }

            lua_pushliteral(L, "\n\t");
            lua_getinfo(co, "Snl", &ar);
            lua_pushfstring(L, "%s:", ar.short_src);

            if (ar.currentline > 0) {
                lua_pushfstring(L, "%d:", ar.currentline);
            }

            if (*ar.namewhat != '\0') {  /* is there a name? */
                lua_pushfstring(L, " in function " LUA_QS, ar.name);

            } else {
                if (*ar.what == 'm') {  /* main? */
                    lua_pushliteral(L, " in main chunk");

                } else if (*ar.what == 'C' || *ar.what == 't') {
                    lua_pushliteral(L, " ?");  /* C function or tail call */

                } else {
                    lua_pushfstring(L, " in function <%s:%d>",
                                    ar.short_src, ar.linedefined);
                }
            }
        }

        if (lua_gettop(L) - base >= 15) {
            lua_concat(L, lua_gettop(L) - base);
        }

        /* check if the coroutine has a parent coroutine*/
        coctx = coctx->parent_co_ctx;
        if (!coctx || coctx->co_status == NGX_HTTP_LUA_CO_DEAD) {
            break;
        }

        co = coctx->co;
    }

    lua_concat(L, lua_gettop(L) - base);
    return 1;
}

/* lua_pcall()的错误跟踪函数，以打印错误栈 */
int
ngx_http_lua_traceback(lua_State *L)
{
    if (!lua_isstring(L, 1)) { /* 'message' not a string? */
        return 1;  /* keep it intact */
    }

    lua_getglobal(L, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }

    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }

    lua_pushvalue(L, 1);    /* pass error message */
    lua_pushinteger(L, 2);  /* skip this function and traceback */
    lua_call(L, 2, 1);      /* call debug.traceback([thread,] [message [, level]]) */
    return 1;
}


static void
ngx_http_lua_inject_arg_api(lua_State *L)
{
    lua_pushliteral(L, "arg");
    lua_newtable(L);    /*  .arg table aka {} */

    /* 创建ngx.arg的metatable表 */
    lua_createtable(L, 0 /* narr */, 2 /* nrec */);

    lua_pushcfunction(L, ngx_http_lua_param_get);
    lua_setfield(L, -2, "__index");    /* 查找 */

    lua_pushcfunction(L, ngx_http_lua_param_set);
    lua_setfield(L, -2, "__newindex"); /* 赋值 */

    lua_setmetatable(L, -2);    /*  tie the metatable to param table */

    dd("top: %d, type -1: %s", lua_gettop(L), luaL_typename(L, -1));

    /* 新建表赋值给 ngx.arg */
    lua_rawset(L, -3);
}


static int
ngx_http_lua_param_get(lua_State *L)
{
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_request_t          *r;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return 0;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "ctx not found");
    }

    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_SET
                               | NGX_HTTP_LUA_CONTEXT_BODY_FILTER);

    if (ctx->context & (NGX_HTTP_LUA_CONTEXT_SET)) {
        return ngx_http_lua_setby_param_get(L);
    }

    /* ctx->context & (NGX_HTTP_LUA_CONTEXT_BODY_FILTER) */

    return ngx_http_lua_body_filter_param_get(L);
}


static int
ngx_http_lua_param_set(lua_State *L)
{
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_request_t          *r;

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return 0;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "ctx not found");
    }

    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_BODY_FILTER);

    return ngx_http_lua_body_filter_param_set(L, r, ctx);
}


ngx_http_lua_co_ctx_t *
ngx_http_lua_get_co_ctx(lua_State *L, ngx_http_lua_ctx_t *ctx)
{
    ngx_uint_t                   i;
    ngx_list_part_t             *part;
    ngx_http_lua_co_ctx_t       *coctx;

    if (L == ctx->entry_co_ctx.co) {
        return &ctx->entry_co_ctx;
    }

    if (ctx->user_co_ctx == NULL) {
        return NULL;
    }

    part = &ctx->user_co_ctx->part;
    coctx = part->elts;

    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            coctx = part->elts;
            i = 0;
        }

        if (coctx[i].co == L) {
            return &coctx[i];
        }
    }

    return NULL;
}


ngx_http_lua_co_ctx_t *
ngx_http_lua_create_co_ctx(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx)
{
    ngx_http_lua_co_ctx_t       *coctx;

    if (ctx->user_co_ctx == NULL) {
        ctx->user_co_ctx = ngx_list_create(r->pool, 4,
                                           sizeof(ngx_http_lua_co_ctx_t));
        if (ctx->user_co_ctx == NULL) {
            return NULL;
        }
    }

    coctx = ngx_list_push(ctx->user_co_ctx);
    if (coctx == NULL) {
        return NULL;
    }

    ngx_memzero(coctx, sizeof(ngx_http_lua_co_ctx_t));

    coctx->co_ref = LUA_NOREF;

    return coctx;
}


/* this is for callers other than the content handler */
ngx_int_t
ngx_http_lua_run_posted_threads(ngx_connection_t *c, lua_State *L,
    ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx)
{
    ngx_int_t                        rc;
    ngx_http_lua_posted_thread_t    *pt;

    for ( ;; ) {
        if (c->destroyed) {
            return NGX_DONE;
        }

        pt = ctx->posted_threads;
        if (pt == NULL) {
            return NGX_DONE;
        }

        ctx->posted_threads = pt->next;

        ngx_http_lua_probe_run_posted_thread(r, pt->co_ctx->co,
                                             (int) pt->co_ctx->co_status);

        if (pt->co_ctx->co_status != NGX_HTTP_LUA_CO_RUNNING) {
            continue;
        }

        ctx->cur_co_ctx = pt->co_ctx;

        rc = ngx_http_lua_run_thread(L, r, ctx, 0);

        if (rc == NGX_AGAIN) {
            continue;
        }

        if (rc == NGX_DONE) {
            ngx_http_lua_finalize_request(r, NGX_DONE);
            continue;
        }

        /* rc == NGX_ERROR || rc >= NGX_OK */

        if (ctx->entered_content_phase) {
            ngx_http_lua_finalize_request(r, rc);
        }

        return rc;
    }

    /* impossible to reach here */
}


ngx_int_t
ngx_http_lua_post_thread(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx,
    ngx_http_lua_co_ctx_t *coctx)
{
    ngx_http_lua_posted_thread_t  **p;
    ngx_http_lua_posted_thread_t   *pt;

    pt = ngx_palloc(r->pool, sizeof(ngx_http_lua_posted_thread_t));
    if (pt == NULL) {
        return NGX_ERROR;
    }

    pt->co_ctx = coctx;
    pt->next = NULL;

    for (p = &ctx->posted_threads; *p; p = &(*p)->next) { /* void */ }

    *p = pt;

    return NGX_OK;
}


static void
ngx_http_lua_finalize_threads(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx, lua_State *L)
{
#ifdef NGX_LUA_USE_ASSERT
    int                              top;
#endif
    int                              inited = 0, ref;
    ngx_uint_t                       i;
    ngx_list_part_t                 *part;
    ngx_http_lua_co_ctx_t           *cc, *coctx;

#ifdef NGX_LUA_USE_ASSERT
    top = lua_gettop(L);
#endif

#if 1
    coctx = ctx->on_abort_co_ctx;
    if (coctx && coctx->co_ref != LUA_NOREF) {
        if (coctx->co_status != NGX_HTTP_LUA_CO_SUSPENDED) {
            /* the on_abort thread contributes to the coctx->uthreads
             * counter only when it actually starts running */
            ngx_http_lua_cleanup_pending_operation(coctx);
            ctx->uthreads--;
        }

        ngx_http_lua_probe_thread_delete(r, coctx->co, ctx);

        lua_pushlightuserdata(L, &ngx_http_lua_coroutines_key);
        lua_rawget(L, LUA_REGISTRYINDEX);
        inited = 1;

        luaL_unref(L, -1, coctx->co_ref);
        coctx->co_ref = LUA_NOREF;

        coctx->co_status = NGX_HTTP_LUA_CO_DEAD;
        ctx->on_abort_co_ctx = NULL;
    }
#endif

    if (ctx->user_co_ctx) {
        part = &ctx->user_co_ctx->part;
        cc = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                cc = part->elts;
                i = 0;
            }

            coctx = &cc[i];

            ref = coctx->co_ref;

            if (ref != LUA_NOREF) {
                ngx_http_lua_cleanup_pending_operation(coctx);

                ngx_http_lua_probe_thread_delete(r, coctx->co, ctx);

                if (!inited) {
                    lua_pushlightuserdata(L, &ngx_http_lua_coroutines_key);
                    lua_rawget(L, LUA_REGISTRYINDEX);
                    inited = 1;
                }

                ngx_http_lua_assert(lua_gettop(L) - top == 1);

                luaL_unref(L, -1, ref);
                coctx->co_ref = LUA_NOREF;

                coctx->co_status = NGX_HTTP_LUA_CO_DEAD;
                ctx->uthreads--;
            }
        }

        ctx->user_co_ctx = NULL;
    }

    ngx_http_lua_assert(ctx->uthreads == 0);

    coctx = &ctx->entry_co_ctx;

    ref = coctx->co_ref;
    if (ref != LUA_NOREF) {
        ngx_http_lua_cleanup_pending_operation(coctx);

        ngx_http_lua_probe_thread_delete(r, coctx->co, ctx);

        if (!inited) {
            lua_pushlightuserdata(L, &ngx_http_lua_coroutines_key);
            lua_rawget(L, LUA_REGISTRYINDEX);
            inited = 1;
        }

        ngx_http_lua_assert(lua_gettop(L) - top == 1);

        luaL_unref(L, -1, coctx->co_ref);
        coctx->co_ref = LUA_NOREF;
        coctx->co_status = NGX_HTTP_LUA_CO_DEAD;
    }

    if (inited) {
        lua_pop(L, 1);
    }
}


static ngx_int_t
ngx_http_lua_post_zombie_thread(ngx_http_request_t *r,
    ngx_http_lua_co_ctx_t *parent, ngx_http_lua_co_ctx_t *thread)
{
    ngx_http_lua_posted_thread_t  **p;
    ngx_http_lua_posted_thread_t   *pt;

    pt = ngx_palloc(r->pool, sizeof(ngx_http_lua_posted_thread_t));
    if (pt == NULL) {
        return NGX_ERROR;
    }

    pt->co_ctx = thread;
    pt->next = NULL;

    for (p = &parent->zombie_child_threads; *p; p = &(*p)->next) { /* void */ }

    *p = pt;

    return NGX_OK;
}


static void
ngx_http_lua_cleanup_zombie_child_uthreads(ngx_http_request_t *r,
    lua_State *L, ngx_http_lua_ctx_t *ctx, ngx_http_lua_co_ctx_t *coctx)
{
    ngx_http_lua_posted_thread_t   *pt;

    for (pt = coctx->zombie_child_threads; pt; pt = pt->next) {
        if (pt->co_ctx->co_ref != LUA_NOREF) {
            ngx_http_lua_del_thread(r, L, ctx, pt->co_ctx);
            ctx->uthreads--;
        }
    }

    coctx->zombie_child_threads = NULL;
}


ngx_int_t
ngx_http_lua_check_broken_connection(ngx_http_request_t *r, ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t     *c;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http lua check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;

    if (c->error) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

            if (ngx_del_event(ev, event, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        return NGX_OK;
    }
#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return NGX_OK;
        }

        ev->eof = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, err,
                   "http lua recv(): %d", n);

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return NGX_OK;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        dd("event is active");

        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

#if 1
        if (ngx_del_event(ev, event, 0) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
#endif
    }

    dd("HERE %d", (int) n);

    if (n > 0) {
        return NGX_OK;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            dd("HERE");
            return NGX_OK;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    return NGX_HTTP_CLIENT_CLOSED_REQUEST;
}


void
ngx_http_lua_rd_check_broken_connection(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_event_t                *rev;
    ngx_http_lua_ctx_t         *ctx;

    if (r->done) {
        return;
    }

    rc = ngx_http_lua_check_broken_connection(r, r->connection->read);

    if (rc == NGX_OK) {
        return;
    }

    /* rc == NGX_ERROR || rc > NGX_OK */

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->on_abort_co_ctx == NULL) {
        r->connection->error = 1;
        ngx_http_lua_request_cleanup(ctx, 0);
        ngx_http_lua_finalize_request(r, rc);
        return;
    }

    if (ctx->on_abort_co_ctx->co_status != NGX_HTTP_LUA_CO_SUSPENDED) {

        /* on_abort already run for the current request handler */

        rev = r->connection->read;

        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                ngx_http_lua_request_cleanup(ctx, 0);
                ngx_http_lua_finalize_request(r,
                                              NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        return;
    }

    ctx->uthreads++;
    ctx->resume_handler = ngx_http_lua_on_abort_resume;
    ctx->on_abort_co_ctx->co_status = NGX_HTTP_LUA_CO_RUNNING;
    ctx->cur_co_ctx = ctx->on_abort_co_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua waking up the on_abort callback thread");

    if (ctx->entered_content_phase) {
        r->write_event_handler = ngx_http_lua_content_wev_handler;

    } else {
        r->write_event_handler = ngx_http_core_run_phases;
    }

    r->write_event_handler(r);
}


static ngx_int_t
ngx_http_lua_on_abort_resume(ngx_http_request_t *r)
{
    lua_State                   *vm;
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_http_lua_ctx_t          *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->resume_handler = ngx_http_lua_wev_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua resuming the on_abort callback thread");

#if 0
    ngx_http_lua_probe_info("tcp resume");
#endif

    c = r->connection;
    vm = ngx_http_lua_get_lua_vm(r, ctx);

    rc = ngx_http_lua_run_thread(vm, r, ctx, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx);
    }

    if (rc == NGX_DONE) {
        ngx_http_lua_finalize_request(r, NGX_DONE);
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx);
    }

    if (ctx->entered_content_phase) {
        ngx_http_lua_finalize_request(r, rc);
        return NGX_DONE;
    }

    return rc;
}


ngx_int_t
ngx_http_lua_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
}


void
ngx_http_lua_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_lua_ctx_t              *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx && ctx->cur_co_ctx) {
        ngx_http_lua_cleanup_pending_operation(ctx->cur_co_ctx);
    }

    if (r->connection->fd != (ngx_socket_t) -1) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_http_lua_finalize_fake_request(r, rc);
}


void
ngx_http_lua_finalize_fake_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
#if (NGX_HTTP_SSL)
    ngx_ssl_conn_t            *ssl_conn;
    ngx_http_lua_ssl_ctx_t    *cctx;
#endif

    c = r->connection;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lua finalize fake request: %d, a:%d, c:%d",
                   rc, r == c->data, r->main->count);

    if (rc == NGX_DONE) {
        ngx_http_lua_close_fake_request(r);
        return;
    }

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {

#if (NGX_HTTP_SSL)

        if (r->connection->ssl) {
            ssl_conn = r->connection->ssl->connection;
            if (ssl_conn) {
                c = ngx_ssl_get_connection(ssl_conn);

                if (c && c->ssl) {
                    cctx = ngx_http_lua_ssl_get_ctx(c->ssl->connection);
                    if (cctx != NULL) {
                        cctx->exit_code = 0;
                    }
                }
            }
        }

#endif

        ngx_http_lua_close_fake_request(r);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        ngx_del_timer(c->write);
    }

    ngx_http_lua_close_fake_request(r);
}


static void
ngx_http_lua_close_fake_request(ngx_http_request_t *r)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lua fake request count:%d", r->count);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http lua fake request "
                      "count is zero");
    }

    r->count--;

    if (r->count) {
        return;
    }

    ngx_http_lua_free_fake_request(r);
    ngx_http_lua_close_fake_connection(c);
}


void
ngx_http_lua_free_fake_request(ngx_http_request_t *r)
{
    ngx_log_t                 *log;
    ngx_http_cleanup_t        *cln;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http lua close fake "
                   "request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "http lua fake request "
                      "already closed");
        return;
    }

    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    r->request_line.len = 0;

    r->connection->destroyed = 1;
}


void
ngx_http_lua_close_fake_connection(ngx_connection_t *c)
{
    ngx_pool_t          *pool;
    ngx_connection_t    *saved_c = NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lua close fake http connection %p", c);

    c->destroyed = 1;

    pool = c->pool;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    /* we temporarily use a valid fd (0) to make ngx_free_connection happy */

    c->fd = 0;

    if (ngx_cycle->files) {
        saved_c = ngx_cycle->files[0];
    }

    ngx_free_connection(c);

    c->fd = (ngx_socket_t) -1;

    if (ngx_cycle->files) {
        ngx_cycle->files[0] = saved_c;
    }

    if (pool) {
        ngx_destroy_pool(pool);
    }
}

/* 解析配置http{}后，新建并初始化Lua虚拟机环境 */
lua_State *
ngx_http_lua_init_vm(lua_State *parent_vm, ngx_cycle_t *cycle,
    ngx_pool_t *pool, ngx_http_lua_main_conf_t *lmcf, ngx_log_t *log,
    ngx_pool_cleanup_t **pcln)
{
    lua_State                       *L;
    ngx_uint_t                       i;
    ngx_pool_cleanup_t              *cln;
    ngx_http_lua_preload_hook_t     *hook;
    ngx_http_lua_vm_state_t         *state;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    /* 创建lua虚拟机实例 */
    L = ngx_http_lua_new_state(parent_vm, cycle, lmcf, log);
    if (L == NULL) {
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "lua initialize the "
                   "global Lua VM %p", L);

    /* 注册lua虚拟机清理句柄 */
    cln->handler = ngx_http_lua_cleanup_vm;

    state = ngx_alloc(sizeof(ngx_http_lua_vm_state_t), log);
    if (state == NULL) {
        return NULL;
    }
    state->vm = L;
    state->count = 1;

    cln->data = state;

    if (pcln) {
        *pcln = cln;
    }

    /* 动态加载其他模块儿 */
    if (lmcf->preload_hooks) {

        /* register the 3rd-party module's preload hooks */

        lua_getglobal(L, "package");
        lua_getfield(L, -1, "preload");

        hook = lmcf->preload_hooks->elts;

        for (i = 0; i < lmcf->preload_hooks->nelts; i++) {

            ngx_http_lua_probe_register_preload_package(L, hook[i].package);

            lua_pushcfunction(L, hook[i].loader);
            lua_setfield(L, -2, (char *) hook[i].package);
        }

        lua_pop(L, 2);
    }

    return L;
}


void
ngx_http_lua_cleanup_vm(void *data)
{
    lua_State                       *L;
    ngx_http_lua_vm_state_t         *state = data;

#if (DDEBUG)
    if (state) {
        dd("cleanup VM: c:%d, s:%p", (int) state->count, state->vm);
    }
#endif

    if (state) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "lua decrementing the reference count for Lua VM: %i",
                       state->count);

        if (--state->count == 0) {
            L = state->vm;
            ngx_http_lua_cleanup_conn_pools(L);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "lua close the global Lua VM %p", L);
            lua_close(L);
            ngx_free(state);
        }
    }
}


ngx_connection_t *
ngx_http_lua_create_fake_connection(ngx_pool_t *pool)
{
    ngx_log_t               *log;
    ngx_connection_t        *c;
    ngx_connection_t        *saved_c = NULL;

    /* (we temporarily use a valid fd (0) to make ngx_get_connection happy) */
    if (ngx_cycle->files) {
        saved_c = ngx_cycle->files[0];
    }

    c = ngx_get_connection(0, ngx_cycle->log);

    if (ngx_cycle->files) {
        ngx_cycle->files[0] = saved_c;
    }

    if (c == NULL) {
        return NULL;
    }

    c->fd = (ngx_socket_t) -1;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    if (pool) {
        c->pool = pool;

    } else {
        c->pool = ngx_create_pool(128, c->log);
        if (c->pool == NULL) {
            goto failed;
        }
    }

    log = ngx_pcalloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        goto failed;
    }

    c->log = log;
    c->log->connection = c->number;
    c->log->action = NULL;
    c->log->data = NULL;

    c->log_error = NGX_ERROR_INFO;

#if 0
    c->buffer = ngx_create_temp_buf(c->pool, 2);
    if (c->buffer == NULL) {
        goto failed;
    }

    c->buffer->start[0] = CR;
    c->buffer->start[1] = LF;
#endif

    c->error = 1;

    dd("created fake connection: %p", c);

    return c;

failed:

    ngx_http_lua_close_fake_connection(c);
    return NULL;
}


ngx_http_request_t *
ngx_http_lua_create_fake_request(ngx_connection_t *c)
{
    ngx_http_request_t      *r;

    r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        return NULL;
    }

    c->requests++;

    r->pool = c->pool;

    dd("r pool allocated: %d", (int) (sizeof(ngx_http_lua_ctx_t)
       + sizeof(void *) * ngx_http_max_module + sizeof(ngx_http_cleanup_t)));

#if 0
    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        goto failed;
    }

    r->header_in = c->buffer;
    r->header_end = c->buffer->start;

    if (ngx_list_init(&r->headers_out.headers, r->pool, 0,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        goto failed;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 0,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        goto failed;
    }
#endif

    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        return NULL;
    }

#if 0
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                               * sizeof(ngx_http_variable_value_t));
    if (r->variables == NULL) {
        goto failed;
    }
#endif

    r->connection = c;

    r->headers_in.content_length_n = 0;
    c->data = r;
#if 0
    hc->request = r;
    r->http_connection = hc;
#endif
    r->signature = NGX_HTTP_MODULE;
    r->main = r;
    r->count = 1;

    r->method = NGX_HTTP_UNKNOWN;

    r->headers_in.keep_alive_n = -1;
    r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
    r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;
    r->discard_body = 1;

    dd("created fake request %p", r);

    return r;
}


ngx_int_t
ngx_http_lua_report(ngx_log_t *log, lua_State *L, int status,
    const char *prefix)
{
    const char      *msg;

    if (status && !lua_isnil(L, -1)) {
        msg = lua_tostring(L, -1);
        if (msg == NULL) {
            msg = "unknown error";
        }

        ngx_log_error(NGX_LOG_ERR, log, 0, "%s error: %s", prefix, msg);
        lua_pop(L, 1);
    }

    /* force a full garbage-collection cycle */
    lua_gc(L, LUA_GCCOLLECT, 0);

    return status == 0 ? NGX_OK : NGX_ERROR;
}


int
ngx_http_lua_do_call(ngx_log_t *log, lua_State *L)
{
    int                 status, base;
#if (NGX_PCRE)
    ngx_pool_t         *old_pool;
#endif

    /* 设定错误处理的跟踪函数 */
    base = lua_gettop(L);  /* function index */
    lua_pushcfunction(L, ngx_http_lua_traceback);  /* push traceback function */
    lua_insert(L, base);   /* put it under chunk and args */

#if (NGX_PCRE)
    old_pool = ngx_http_lua_pcre_malloc_init(ngx_cycle->pool);
#endif

    /* 执行原栈顶函数 */
    status = lua_pcall(L, 0, 0, base);

#if (NGX_PCRE)
    ngx_http_lua_pcre_malloc_done(old_pool);
#endif

    /* u移除跟踪函数 */
    lua_remove(L, base);

    return status;
}

/* 获取当前Lua模块儿所处的执行阶段，如 NGX_HTTP_LUA_CONTEXT_CONTENT */
static int
ngx_http_lua_get_raw_phase_context(lua_State *L)
{
    ngx_http_request_t      *r;
    ngx_http_lua_ctx_t      *ctx;

    r = lua_touserdata(L, 1);
    if (r == NULL) {
        return 0;
    }
    /* 存储函数为 ngx_http_set_ctx() */
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {  /* #define ngx_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index] */
        return 0;
    }

    lua_pushinteger(L, (int) ctx->context);
    return 1;
}


ngx_http_cleanup_t *
ngx_http_lua_cleanup_add(ngx_http_request_t *r, size_t size)
{
    ngx_http_cleanup_t  *cln;
    ngx_http_lua_ctx_t  *ctx;

    if (size == 0) {
        ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

        r = r->main;

        if (ctx != NULL && ctx->free_cleanup) {
            cln = ctx->free_cleanup;
            ctx->free_cleanup = cln->next;

            dd("reuse cleanup: %p", cln);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua http cleanup reuse: %p", cln);

            cln->handler = NULL;
            cln->next = r->cleanup;

            r->cleanup = cln;

            return cln;
        }
    }

    return ngx_http_cleanup_add(r, size);
}


void
ngx_http_lua_cleanup_free(ngx_http_request_t *r, ngx_http_cleanup_pt *cleanup)
{
    ngx_http_cleanup_t  **last;
    ngx_http_cleanup_t   *cln;
    ngx_http_lua_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return;
    }

    r = r->main;

    cln = (ngx_http_cleanup_t *)
              ((u_char *) cleanup - offsetof(ngx_http_cleanup_t, handler));

    dd("cln: %p, cln->handler: %p, &cln->handler: %p",
       cln, cln->handler, &cln->handler);

    last = &r->cleanup;

    while (*last) {
        if (*last == cln) {
            *last = cln->next;

            cln->next = ctx->free_cleanup;
            ctx->free_cleanup = cln;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua http cleanup free: %p", cln);

            return;
        }

        last = &(*last)->next;
    }
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
