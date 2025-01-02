package = "kong-oidc"
version = "1.3.2-1"
source = {
    url = "git://github.com/mehmetdgp/kong-oidc",
    tag = "master",
    dir = "kong-oidc"
}
dependencies = {
    "lua-ffi-zlib >= 0.5",
    "lua-resty-openssl >= 0.8.0",
    "lua-resty-jwt >= 0.2.3"
}
build = {
    type = "builtin",
    modules = {
    ["kong.plugins.oidc.filter"] = "kong/plugins/oidc/filter.lua",
    ["kong.plugins.oidc.handler"] = "kong/plugins/oidc/handler.lua",
    ["kong.plugins.oidc.schema"] = "kong/plugins/oidc/schema.lua",
    ["kong.plugins.oidc.session"] = "kong/plugins/oidc/session.lua",
    ["kong.plugins.oidc.utils"] = "kong/plugins/oidc/utils.lua",
    ["kong.plugins.oidc.openidc"] = "kong/plugins/oidc/openidc.lua",
    ["kong.plugins.oidc.api"] = "kong/plugins/oidc/api.lua"
    }
}
