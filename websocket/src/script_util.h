#pragma once

#include <dmsdk/sdk.h>

namespace dmScript {
    bool        CheckBool(lua_State *L, int numArg);
    bool        CheckBoold(lua_State *L, int numArg, int def);
    lua_Number  CheckNumberd(lua_State *L, int numArg, lua_Number def);
    char*       CheckStringd(lua_State *L, int numArg, const char* def);
    lua_Number  CheckTableNumber(lua_State *L, int numArg, const char* field, lua_Number def);
    char*       CheckTableString(lua_State *L, int numArg, const char* field, char* def);
} // namespace