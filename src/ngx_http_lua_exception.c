
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_util.h"


/*  Lua虚拟机崩溃后，长跳转的点；
    长跳转被宏NGX_LUA_EXCEPTION_TRY、NGX_LUA_EXCEPTION_CATCH、NGX_LUA_EXCEPTION_THROW实现
    longjmp mark for restoring nginx execution after Lua VM crashing */
jmp_buf ngx_http_lua_exception;

/**
 * Override default Lua panic handler, output VM crash reason to nginx error
 * log, and restore execution to the nearest jmp-mark.
 *
 * @param L Lua state pointer
 * @retval Long jump to the nearest jmp-mark, never returns.
 * @note nginx request pointer should be stored in Lua thread's globals table
 * in order to make logging working.
 * */
/* Lua执行环境发生异常崩溃后，执行的自定义panic函数；以防止默认行为(exit())
   使得nginx worker进程退出 */
int
ngx_http_lua_atpanic(lua_State *L)
{
#ifdef NGX_LUA_ABORT_AT_PANIC
    abort();
#else
    u_char                  *s = NULL;
    size_t                   len = 0;

    /* 提取栈顶的错误信息 */
    if (lua_type(L, -1) == LUA_TSTRING) {
        s = (u_char *) lua_tolstring(L, -1, &len);
    }
    if (s == NULL) {
        s = (u_char *) "unknown reason";
        len = sizeof("unknown reason") - 1;
    }

    /* 触发worker进程优雅退出 */
    ngx_log_stderr(0, "lua atpanic: Lua VM crashed, reason: %*s", len, s);
    ngx_quit = 1;

    /* 跳转到最近的注册点，即 NGX_LUA_EXCEPTION_TRY 宏所在的位置
       restore nginx execution */
    NGX_LUA_EXCEPTION_THROW(1);

    /* impossible to reach here */
#endif
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
