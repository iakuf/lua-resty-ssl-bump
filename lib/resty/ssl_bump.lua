local _M = {}

local ssl = require("ngx.ssl") 
local openssl_pkey = require("resty.openssl.pkey")
local openssl_bignum = require("resty.openssl.bn")
local openssl_csr = require("resty.openssl.x509.csr")
local openssl_x509_name = require("resty.openssl.x509.name")
local openssl_x509 = require("resty.openssl.x509")
local openssl_rand = require("resty.openssl.rand")
local altname = require("resty.openssl.x509.altname")

local cert_cache = ngx.shared.cert_cache

-- CA证书和私钥的PEM内容
local ca_cert
local ca_pkey
local config

-- 初始化函数，传入证书和密钥的路径以及配置
function _M.init(cert_path, key_path, cfg)
    -- 加载CA证书
    local file = io.open(cert_path, "r")
    if not file then
        ngx.log(ngx.ERR, "failed to open CA cert file: ", cert_path)
        return false, "failed to open CA cert file"
    end
    local ca_cert_pem = file:read("*a")

    file:close()
    local err
    ca_cert, err = openssl_x509.new(ca_cert_pem)
    if not ca_cert then
        ngx.log(ngx.ERR, "failed to load CA cert: ", err)
        return false, "failed to load CA cert"
    end

    -- 加载CA私钥
    file = io.open(key_path, "r")
    if not file then
        ngx.log(ngx.ERR, "failed to open CA key file: ", key_path)
        return false, "failed to open CA key file"
    end
    local ca_pkey_pem = file:read("*a")
    file:close()

    ca_pkey, err = openssl_pkey.new(ca_pkey_pem)
    if not ca_pkey then
        ngx.log(ngx.ERR, "failed to load CA pkey: ", err)
        return false, "failed to load CA pkey"
    end

    config = cfg

    return true
end

-- 创建证书
local function generateCert(domain)
    -- 生成和签署 SSL 证书时
    -- step1: 生成新的密钥对：为待签名的证书生成一个新的公钥和私钥。
    local pkey, err = openssl_pkey.new({ type = "RSA", bits = 2048 })
    if not pkey then
        ngx.log(ngx.ERR, "failed to create pkey: ", err)
        return
    end
    
    -- step2 生成 CSR（证书签名请求）：使用新生成的私钥和相关信息（如域名、组织信息等）生成 CSR。
    local csr, err = openssl_csr.new()
    if not csr then
        ngx.log(ngx.ERR, "failed to create csr: ", err)
        return
    end
    
    local subject = openssl_x509_name.new()
    -- local _, err = subject:add("C", "CN")
    --     :add("ST", "Beijing")
    --     :add("L", "Beijing")
    --     :add("O", "Geelevel Corp")
    --     :add("CN", domain)
    subject:add("C", config.C or "CN")
       :add("ST", config.ST or "Beijing")
       :add("L", config.L or "Beijing")
       :add("O", config.O or "Unkown Corp")
       :add("CN", domain)

    local ok, err = csr:set_subject_name(subject)
    if not ok then
        ngx.log(ngx.ERR, "set subject name failed: ", err)
        return nil, err
    end
    csr:set_pubkey(pkey)
    
    -- step3 使用 CA 签署 CSR：用 CA 的私钥签署这个 CSR，生成最终的证书。
    local cert, err = openssl_x509.new()
    if not cert then
        ngx.log(ngx.ERR, "failed to create cert: ", err)
        return
    end
    
    cert:set_version(3)
    cert:set_serial_number(openssl_bignum.from_binary(openssl_rand.bytes(16)))
    cert:set_pubkey(csr:get_pubkey()) -- 需要使用 csr 的公钥
    local ok, err = cert:set_subject_name(subject) -- 设置 ssl 证书的主题信息，如国家， 地区，机构 
    if not ok then
        ngx.log(ngx.ERR, "set subject cert fail: ", err)
    end

    -- 主题备用名（SAN）
    local alt = altname.new():add( "DNS", domain)
    local _, err = cert:set_subject_alt_name(alt)
    if err then
      return nil, nil, err
    end

    cert:set_not_before(ngx.time())
    cert:set_not_after(ngx.time() + 365 * 24 * 60 * 60)  -- 一年有效期
    cert:set_issuer_name(ca_cert:get_subject_name()) -- 谁签发的
    cert:sign(ca_pkey) -- 需要使用 ca 的私钥来签这个 ssl 的证书
    
    -- 获取证书的PEM格式
    local cert_pem, err = cert:to_PEM()
    if not cert_pem then
        ngx.log(ngx.ERR, "failed to get cert PEM: ", err)
        return
    end
    
    -- 获取私钥的PEM格式
    local pkey_pem, err = pkey:to_PEM("private")
    if not pkey_pem then
        ngx.log(ngx.ERR, "failed to get pkey PEM: ", err)
        return
    end
    return cert_pem, pkey_pem
end

local function convertToWildcard(domain)
    -- 将域名分割为部分
    local parts = {}
    for part in domain:gmatch("[^.]+") do
        table.insert(parts, part)
    end

    local num_parts = #parts
    if num_parts <= 2 then
        -- 如果域名部分少于两个，直接返回原域名
        return "*.".. domain
    else 
        -- 移除表中的第一个元素
        table.remove(parts, 1)

        -- 从剩余部分构建泛域名
        return "*." .. table.concat(parts, ".")
    end
end


function _M.run() 
    local domain, err = ssl.server_name()
    if not domain then
        ngx.log(ngx.ERR, "Failed to get server name: ", err)
        return ngx.exit(ngx.ERROR)
    end
    
    -- 取泛域名
    local wildcard_domain = convertToWildcard(domain)
    
    -- 尝试从缓存中获取证书和密钥
    local cache_key = "cert:" .. wildcard_domain
    local cert_pem = cert_cache:get(cache_key .. ":cert")
    local key_pem = cert_cache:get(cache_key .. ":key")
    
     -- 如果缓存中没有证书或密钥，则生成新的，并存入缓存
    if not cert_pem or not key_pem then
        cert_pem, key_pem = generateCert(wildcard_domain)
        if not cert_pem or not key_pem then
            ngx.log(ngx.ERR, "Failed to generate certificate for domain: ", wildcard_domain)
            return ngx.exit(ngx.ERROR)
        end
    
        cert_cache:set(cache_key .. ":cert", cert_pem, 3600*24) -- 缓存1小时
        cert_cache:set(cache_key .. ":key", key_pem, 3600*24)
    end
    
    local der_cert, err = ssl.parse_pem_cert(cert_pem)
    if not der_cert then
        ngx.log(ngx.ERR, "Failed to parse PEM cert: ", err)
        return ngx.exit(ngx.ERROR)
    end
    
    local der_key, err = ssl.parse_pem_priv_key(key_pem)
    if not der_key then
        ngx.log(ngx.ERR, "Failed to parse PEM key: ", err)
        return ngx.exit(ngx.ERROR)
    end
    
    
    local ok, err = ssl.set_cert(der_cert)
    if not ok then
        ngx.log(ngx.ERR, "Failed to set certificate: ", err)
        return ngx.exit(ngx.ERROR)
    end
    
    ok, err = ssl.set_priv_key(der_key)
end

return _M
