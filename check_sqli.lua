
function access_check(r)
    local uri = r.unparsed_uri
    local ip = r.useragent_ip

    local http = require("socket.http")
    local ltn12 = require("ltn12")

    local response_body = {}
    local api_url = "http://127.0.0.1:5000/check?uri=" .. uri .. "&ip=" .. ip

    local res, code = http.request{
        url = api_url,
        sink = ltn12.sink.table(response_body)
    }

    if code == 403 then
        r:err("Bloqueado por WebGuardian: " .. ip)
        return 403
    end

    return apache2.DECLINED
end
