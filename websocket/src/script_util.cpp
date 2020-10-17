#include "script_util.h"

namespace dmScript {

bool CheckBool(lua_State *L, int numArg)
{
    bool b = false;
    if (lua_isboolean(L, numArg))
    {
        b = lua_toboolean(L, numArg);
    }
    else
    {
        luaL_typerror(L, numArg, lua_typename(L, LUA_TBOOLEAN));
    }
    return b;
}

bool CheckBoold(lua_State *L, int numArg, int def)
{
    int type = lua_type(L, numArg);
    if (type != LUA_TNONE && type != LUA_TNIL)
    {
        return CheckBool(L, numArg);
    }
    return def;
}

lua_Number CheckNumberd(lua_State *L, int numArg, lua_Number def)
{
    int type = lua_type(L, numArg);
    if (type != LUA_TNONE && type != LUA_TNIL)
    {
        return luaL_checknumber(L, numArg);
    }
    return def;
}

char* CheckStringd(lua_State *L, int numArg, const char* def)
{
    int type = lua_type(L, numArg);
    if (type != LUA_TNONE && type != LUA_TNIL)
    {
        return (char*)luaL_checkstring(L, numArg);
    }
    return (char*)def;
}

lua_Number CheckTableNumber(lua_State *L, int numArg, const char* field, lua_Number def)
{
    lua_Number result = def;
    if(lua_istable(L, numArg))
    {
        lua_getfield(L, numArg, field);
        if(!lua_isnil(L, -1))
        {
            result = luaL_checknumber(L, -1);
        }
        lua_pop(L, 1);
    }
    return result;
}

char* CheckTableString(lua_State *L, int numArg, const char* field, char* def)
{
    char* result = def;
    if(lua_istable(L, numArg))
    {
        lua_getfield(L, numArg, field);
        if(!lua_isnil(L, -1))
        {
            result = (char*)luaL_checkstring(L, -1);
        }
        lua_pop(L, 1);
    }
    return result;
}

} // namespace