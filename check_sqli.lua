function access_check(r)
    local uri = r.unparsed_uri or ""
    local ip = r.useragent_ip or "desconocido"

    -- Mensaje de trazado
    r:info(" ^=^{   ^o WebGuardian ejecutando revisi  n para URI: " .. uri .. " desde IP: " .. ip)

    -- Cargar rutas para los m  dulos de red LuaSocket
    package.path = package.path .. ";/usr/share/lua/5.4/?.lua;/usr/lib/x86_64-linux-gnu/lua/5.4/?.lua"
    package.cpath = package.cpath .. ";/usr/lib/x86_64-linux-gnu/lua/5.4/?.so"

    -- Requerir m  dulos
    local http = require("socket.http")
    local ltn12 = require("ltn12")

    local response_body = {}
    local encoded_uri = string.gsub(uri, " ", "%%20")  -- escapado m  nimo b  sico

    local api_url = "http://127.0.0.1:5000/check?uri=" .. encoded_uri .. "&ip=" .. ip
    r:info(" ^=   Consultando API Flask: " .. api_url)

    local res, code = http.request{
        url = api_url,
        sink = ltn12.sink.table(response_body)
    }

    if not res then
        r:err(" ^}^l Error al conectar con WebGuardian API.")
        return apache2.DECLINED  -- No se bloquea si hay fallo de conexi  n
    end

    r:info(" ^=^s  C  digo de respuesta de WebGuardian: " .. tostring(code))

    if code == 403 then
        r:err(" ^}^l Bloqueado por WebGuardian (SQLi detectado) desde IP: " .. ip)
        return 403
    end

    return apache2.DECLINED
end
