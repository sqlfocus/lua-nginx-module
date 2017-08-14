
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <nginx.h>
#include "ngx_http_lua_rewriteby.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_cache.h"


static ngx_int_t ngx_http_lua_rewrite_by_chunk(lua_State *L,
    ngx_http_request_t *r);

/* 配置指令“rewrite_by_lua_file”的执行入口 */
ngx_int_t
ngx_http_lua_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_lua_loc_conf_t     *llcf;
    ngx_http_lua_ctx_t          *ctx;
    ngx_int_t                    rc;
    ngx_http_lua_main_conf_t    *lmcf;

    /* XXX we need to take into account ngx_rewrite's location dump */
    if (r->uri_changed) {
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua rewrite handler, uri:\"%V\" c:%ud", &r->uri,
                   r->main->count);

    /* 移动到所有注册句柄的最后，也即Lua脚本最后执行 */
    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);
    if (!lmcf->postponed_to_rewrite_phase_end) {
        ngx_http_core_main_conf_t       *cmcf;
        ngx_http_phase_handler_t        tmp;
        ngx_http_phase_handler_t        *ph;
        ngx_http_phase_handler_t        *cur_ph;
        ngx_http_phase_handler_t        *last_ph;

        lmcf->postponed_to_rewrite_phase_end = 1;

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        ph = cmcf->phase_engine.handlers;
        cur_ph = &ph[r->phase_handler];
        last_ph = &ph[cur_ph->next - 1];

#if 0
        if (cur_ph == last_ph) {
            dd("XXX our handler is already the last rewrite phase handler");
        }
#endif

        if (cur_ph < last_ph) {
            dd("swaping the contents of cur_ph and last_ph...");

            tmp      = *cur_ph;

            memmove(cur_ph, cur_ph + 1,
                    (last_ph - cur_ph) * sizeof (ngx_http_phase_handler_t));

            *last_ph = tmp;

            r->phase_handler--; /* redo the current ph */

            return NGX_DECLINED;
        }
    }

    /* =ngx_http_lua_rewrite_handler_file() */
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
    if (llcf->rewrite_handler == NULL) {
        dd("no rewrite handler found");
        return NGX_DECLINED;
    }

    /* 创建Lua上下文环境 */
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    dd("ctx = %p", ctx);
    if (ctx == NULL) {
        ctx = ngx_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* 方式1: 先前已经运行了Lua一段时间，由于条件限制等原因主动yield，此刻可
              通过resume恢复Lua先前的运行环境 */
    dd("entered? %d", (int) ctx->entered_rewrite_phase);
    if (ctx->entered_rewrite_phase) {
        dd("rewriteby: calling wev handler");
        rc = ctx->resume_handler(r);
        dd("rewriteby: wev handler returns %d", (int) rc);

        if (rc == NGX_OK) {
            rc = NGX_DECLINED;
        }

        if (rc == NGX_DECLINED) {
            if (r->header_sent) {
                dd("header already sent");

                /* response header was already generated in access_by_lua*,
                 * so it is no longer safe to proceed to later phases
                 * which may generate responses again */

                if (!ctx->eof) {
                    dd("eof not yet sent");

                    rc = ngx_http_lua_send_chain_link(r, ctx, NULL
                                                     /* indicate last_buf */);
                    if (rc == NGX_ERROR || rc > NGX_OK) {
                        return rc;
                    }
                }

                return NGX_HTTP_OK;
            }
        }

        return rc;
    }

    /* 等待报文体读取完毕 */
    if (ctx->waiting_more_body) {
        return NGX_DONE;
    }

    /* 强制读取报文体，读取完毕后才能进入rewrite阶段处理 */
    if (llcf->force_read_body && !ctx->read_body_done) {
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        rc = ngx_http_read_client_request_body(r,
                                       ngx_http_lua_generic_phase_post_read);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
        (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif

            return rc;
        }

        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    /* 执行，=ngx_http_lua_rewrite_handler_file() */
    dd("calling rewrite handler");
    return llcf->rewrite_handler(r);
}


ngx_int_t
ngx_http_lua_rewrite_handler_inline(ngx_http_request_t *r)
{
    lua_State                   *L;
    ngx_int_t                    rc;
    ngx_http_lua_loc_conf_t     *llcf;

    dd("rewrite by lua inline");

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
    L = ngx_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = ngx_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->rewrite_src.value.data,
                                       llcf->rewrite_src.value.len,
                                       llcf->rewrite_src_key,
                                       (const char *)
                                       llcf->rewrite_chunkname);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_lua_rewrite_by_chunk(L, r);
}


ngx_int_t
ngx_http_lua_rewrite_handler_file(ngx_http_request_t *r)
{
    lua_State                       *L;
    ngx_int_t                        rc;
    u_char                          *script_path;
    ngx_http_lua_loc_conf_t         *llcf;
    ngx_str_t                        eval_src;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (ngx_http_complex_value(r, &llcf->rewrite_src, &eval_src) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 获取绝对路径 */
    script_path = ngx_http_lua_rebase_path(r->pool, eval_src.data,
                                           eval_src.len);
    if (script_path == NULL) {
        return NGX_ERROR;
    }
    
    /* 获取Lua虚拟机 */
    L = ngx_http_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = ngx_http_lua_cache_loadfile(r->connection->log, L, script_path,
                                     llcf->rewrite_src_key);
    if (rc != NGX_OK) {
        if (rc < NGX_HTTP_SPECIAL_RESPONSE) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return rc;
    }

    /* 执行 */
    return ngx_http_lua_rewrite_by_chunk(L, r);
}


static ngx_int_t
ngx_http_lua_rewrite_by_chunk(lua_State *L, ngx_http_request_t *r)
{
    int                      co_ref;
    lua_State               *co;
    ngx_int_t                rc;
    ngx_event_t             *rev;
    ngx_connection_t        *c;
    ngx_http_lua_ctx_t      *ctx;
    ngx_http_cleanup_t      *cln;

    ngx_http_lua_loc_conf_t     *llcf;

    /* 新建协程，处理当前请求，{{{ new coroutine to handle request */
    co = ngx_http_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine to handle request");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 将编译后的Lua脚本代码块儿移动到新协程，
       move code closure to new coroutine */
    lua_xmove(L, co, 1);

    /* 设定代码块儿的执行环境为新协程的全局表，_G
       set closure's env table to new coroutine's globals table */
    ngx_http_lua_get_globals_table(co);
    lua_setfenv(co, -2);

    /* 记录请求指针到新协程全局表_G["__ngx_req"]
        save nginx request in coroutine globals table */
    ngx_http_lua_set_req(co, r);

    /* 初始化当前请求的Lua上下文， {{{ initialize request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    dd("ctx = %p", ctx);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_lua_reset_ctx(r, L, ctx);

    /* 设置标识，进入rewrite阶段 */
    ctx->entered_rewrite_phase = 1;

    /* 记录新协程信息 */
    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NGX_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    /*  }}} */

    /* 设置清理句柄，{{{ register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = ngx_http_cleanup_add(r, 0);
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_http_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }
    /*  }}} */

    /* 设置当前处理阶段 */
    ctx->context = NGX_HTTP_LUA_CONTEXT_REWRITE;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
    if (llcf->check_client_abort) {
        r->read_event_handler = ngx_http_lua_rd_check_broken_connection;

#if (NGX_HTTP_V2)
        if (!r->stream) {
#endif

        rev = r->connection->read;

        if (!rev->active) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

#if (NGX_HTTP_V2)
        }
#endif

    } else {
        r->read_event_handler = ngx_http_block_reading;
    }

    /* 运行新建协程 */
    rc = ngx_http_lua_run_thread(L, r, ctx, 0);

    /*** 处理完毕，返回 ***/
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    /*** 脚本未完成，主动让出CPU ***/
    c = r->connection;

    if (rc == NGX_AGAIN) {         /* 执行此协程的内建协程 */
        rc = ngx_http_lua_run_posted_threads(c, L, r, ctx);
    } else if (rc == NGX_DONE) {   /* */
        ngx_http_lua_finalize_request(r, NGX_DONE);
        rc = ngx_http_lua_run_posted_threads(c, L, r, ctx);
    }

    /*** 其他 ***/
    if (rc == NGX_OK || rc == NGX_DECLINED) {
        if (r->header_sent) {
            dd("header already sent");

            /* response header was already generated in access_by_lua*,
             * so it is no longer safe to proceed to later phases
             * which may generate responses again */

            if (!ctx->eof) {
                dd("eof not yet sent");

                rc = ngx_http_lua_send_chain_link(r, ctx, NULL
                                                  /* indicate last_buf */);
                if (rc == NGX_ERROR || rc > NGX_OK) {
                    return rc;
                }
            }

            return NGX_HTTP_OK;
        }

        return NGX_DECLINED;
    }

    return rc;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
