/*
** lnetlib.c
** Network library for Lua (myos-specific)
*/

#define lnetlib_c
#define LUA_LIB

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syscalls.h>

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

#define NET_SOCKET_MT "net.socket"

typedef struct NetSocket {
    int fd;
    int closed;
} NetSocket;

static NetSocket* checksocket(lua_State* L, int idx) {
    NetSocket* s = (NetSocket*)luaL_checkudata(L, idx, NET_SOCKET_MT);
    if (s->closed)
        luaL_error(L, "socket is closed");
    return s;
}

static void fill_sockaddr_in(lua_State* L, int addr_idx, int port_idx,
                             struct sockaddr_in* sa) {
    const char* addr_str = luaL_optstring(L, addr_idx, "0.0.0.0");
    int port = (int)luaL_checkinteger(L, port_idx);

    memset(sa, 0, sizeof(*sa));
    sa->sin_family = SOCKET_DOMAIN_AF_INET;
    sa->sin_port = (in_port_t)(((port & 0xff) << 8) | ((port >> 8) & 0xff));

    unsigned int b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    sscanf(addr_str, "%u.%u.%u.%u", &b0, &b1, &b2, &b3);
    uint32_t ip = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    /* store big-endian */
    sa->sin_addr.s_addr = (in_addr_t)(((ip & 0xff000000u) >> 24) |
                                      ((ip & 0x00ff0000u) >> 8) |
                                      ((ip & 0x0000ff00u) << 8) |
                                      ((ip & 0x000000ffu) << 24));
}

static int lnet_socket(lua_State* L) {
    const char* type_str = luaL_optstring(L, 1, "tcp");
    int sock_type, proto;
    if (strcmp(type_str, "udp") == 0) {
        sock_type = SOCKET_TYPE_SOCK_DGRAM;
        proto = SOCKET_PROTO_UDP;
    } else {
        sock_type = SOCKET_TYPE_SOCK_STREAM;
        proto = 0;
    }

    int fd = sys_socket(SOCKET_DOMAIN_AF_INET, sock_type, proto);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "sys_socket failed");
        return 2;
    }

    NetSocket* s = (NetSocket*)lua_newuserdata(L, sizeof(NetSocket));
    s->fd = fd;
    s->closed = 0;
    luaL_setmetatable(L, NET_SOCKET_MT);
    return 1;
}

static int lnet_connect(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    struct sockaddr_in sa;
    fill_sockaddr_in(L, 2, 3, &sa);
    if (sys_connect(s->fd, (const struct sockaddr*)&sa, sizeof(sa)) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "sys_connect failed");
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int lnet_bind(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    struct sockaddr_in sa;
    fill_sockaddr_in(L, 2, 3, &sa);
    if (sys_bind(s->fd, (const struct sockaddr*)&sa, sizeof(sa)) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "sys_bind failed");
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int lnet_listen(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    int backlog = (int)luaL_optinteger(L, 2, 5);
    if (sys_listen(s->fd, backlog) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "sys_listen failed");
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int lnet_accept(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    struct sockaddr_in sa;
    size_t addrlen = sizeof(sa);
    int fd = sys_accept(s->fd, (struct sockaddr*)&sa, &addrlen);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "sys_accept failed");
        return 2;
    }
    NetSocket* client = (NetSocket*)lua_newuserdata(L, sizeof(NetSocket));
    client->fd = fd;
    client->closed = 0;
    luaL_setmetatable(L, NET_SOCKET_MT);
    return 1;
}

static int lnet_send(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    int r = sys_send(s->fd, data, len, 0);
    if (r < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "sys_send failed");
        return 2;
    }
    lua_pushinteger(L, (lua_Integer)r);
    return 1;
}

static int lnet_recv(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    size_t maxlen = (size_t)luaL_checkinteger(L, 2);
    char* buf = (char*)malloc(maxlen);
    if (!buf)
        return luaL_error(L, "out of memory");
    int r = sys_recv(s->fd, buf, maxlen, 0);
    if (r < 0) {
        free(buf);
        lua_pushnil(L);
        lua_pushstring(L, "sys_recv failed");
        return 2;
    }
    lua_pushlstring(L, buf, (size_t)r);
    free(buf);
    return 1;
}

static int lnet_sendto(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    struct sockaddr_in sa;
    fill_sockaddr_in(L, 3, 4, &sa);
    int r = sys_sendto(s->fd, data, len, 0, (const struct sockaddr*)&sa, sizeof(sa));
    if (r < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "sys_sendto failed");
        return 2;
    }
    lua_pushinteger(L, (lua_Integer)r);
    return 1;
}

static int lnet_recvfrom(lua_State* L) {
    NetSocket* s = checksocket(L, 1);
    size_t maxlen = (size_t)luaL_checkinteger(L, 2);
    char* buf = (char*)malloc(maxlen);
    if (!buf)
        return luaL_error(L, "out of memory");

    struct sockaddr_in sa;
    int r = sys_recvfrom(s->fd, buf, maxlen, 0, (struct sockaddr*)&sa, sizeof(sa));
    if (r < 0) {
        free(buf);
        lua_pushnil(L);
        lua_pushstring(L, "sys_recvfrom failed");
        return 2;
    }
    lua_pushlstring(L, buf, (size_t)r);
    free(buf);

    /* decode source IP (stored big-endian) */
    uint32_t ip_be = (uint32_t)sa.sin_addr.s_addr;
    char addr_str[32];
    snprintf(addr_str, sizeof(addr_str), "%u.%u.%u.%u",
             (unsigned)(ip_be & 0xffu),
             (unsigned)((ip_be >> 8) & 0xffu),
             (unsigned)((ip_be >> 16) & 0xffu),
             (unsigned)((ip_be >> 24) & 0xffu));
    lua_pushstring(L, addr_str);

    int port_be = (int)sa.sin_port;
    lua_pushinteger(L, (lua_Integer)(((port_be & 0xff) << 8) | ((port_be >> 8) & 0xff)));
    return 3;
}

static int lnet_close(lua_State* L) {
    NetSocket* s = (NetSocket*)luaL_checkudata(L, 1, NET_SOCKET_MT);
    if (!s->closed) {
        sys_close(s->fd);
        s->closed = 1;
    }
    return 0;
}

static int lnet_fd(lua_State* L) {
    NetSocket* s = (NetSocket*)luaL_checkudata(L, 1, NET_SOCKET_MT);
    lua_pushinteger(L, (lua_Integer)s->fd);
    return 1;
}

static int lnet_tostring(lua_State* L) {
    NetSocket* s = (NetSocket*)luaL_checkudata(L, 1, NET_SOCKET_MT);
    if (s->closed)
        lua_pushstring(L, "net.socket (closed)");
    else
        lua_pushfstring(L, "net.socket (fd=%d)", s->fd);
    return 1;
}

static int lnet_gc(lua_State* L) {
    return lnet_close(L);
}

static const luaL_Reg netlib_socket_mt[] = {
    {"connect", lnet_connect},
    {"bind", lnet_bind},
    {"listen", lnet_listen},
    {"accept", lnet_accept},
    {"send", lnet_send},
    {"recv", lnet_recv},
    {"sendto", lnet_sendto},
    {"recvfrom", lnet_recvfrom},
    {"close", lnet_close},
    {"fd", lnet_fd},
    {"__tostring", lnet_tostring},
    {"__gc", lnet_gc},
    {NULL, NULL}};

static const luaL_Reg netlib[] = {
    {"socket", lnet_socket},
    {NULL, NULL}};

LUAMOD_API int luaopen_net(lua_State* L) {
    luaL_newmetatable(L, NET_SOCKET_MT);
    luaL_setfuncs(L, netlib_socket_mt, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);

    luaL_newlib(L, netlib);
    return 1;
}
