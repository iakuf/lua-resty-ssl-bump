# lua-resty-ssl-bump

A Lua module for dynamic generation and caching of SSL certificates for wildcard domains, similar to Squid's SSL Bump functionality.

## Installation

To install this module, you can use the OpenResty Package Manager (opm):

```
opm get iakuf/lua-resty-ssl-bump
```

## Dependencies

This module requires the `lua-cjson` and `lua-resty-openssl` libraries to work. Ensure that both libraries are installed and accessible in your OpenResty environment.

### Install lua-cjson

You can install `lua-cjson` using OPM:

```
opm get ledgetech/lua-cjson
```

### Install lua-resty-openssl

You can install `lua-resty-openssl` using OPM:

```
opm get fffonion/lua-resty-openssl 
```

## Usage

### Generating Your Own CA Certificate

To generate your own CA certificate, use the following command:

```shell
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -extensions v3_ca -keyout /path/to/ca_cert.key -out /path/to/ca_cert.crt
```

Replace `/path/to/ca_cert.key` and `/path/to/ca_cert.crt` with the actual paths where you want to save your CA key and certificate.

### Nginx Configuration

Add the following configuration to your `nginx.conf` file:

1. **Define shared dictionary**:

```
http {
    lua_shared_dict cert_cache 20m; # Approximately stores 4000 certificate pairs
}
```

1. **Initialize the module in the worker**:

```
http {
    init_worker_by_lua_block {
        local ssl_bump = require("resty.ssl_bump")
        local ok, err = ssl_bump.init("/path/to/ca_cert.crt", "/path/to/ca_cert.key", {
            C = "CN",
            ST = "Beijing",
            L = "Beijing",
            O = "Geelevel Corp"
        })
        if not ok then
            ngx.log(ngx.ERR, "failed to initialize ssl_bump: ", err)
            return
        end
    }
}
```

1. **Set SSL configurations**:

```
http {
    server {
        listen 443 ssl;

        ssl_certificate     /path/to/ca_cert.crt; # 占位
        ssl_certificate_key /path/to/ca_cert.key; # 占位

        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers   on;

        # Dynamic generation of certificates
        ssl_certificate_by_lua_block {
            local ssl_bump = require("resty.ssl_bump")
            ssl_bump.run()
        }

        location / {
            proxy_pass http://your_backend;
        }
    }
}
```

### Example

Here is an example `nginx.conf` file with the necessary configuration:

```
http {
    lua_shared_dict cert_cache 20m; # Approximately stores 4000 certificate pairs

    init_worker_by_lua_block {
        local ssl_bump = require("resty.ssl_bump")
        local ok, err = ssl_bump.init("/path/to/ca_cert.crt", "/path/to/ca_cert.key", {
            C = "CN",
            ST = "Beijing",
            L = "Beijing",
            O = "Geelevel Corp"
        })
        if not ok then
            ngx.log(ngx.ERR, "failed to initialize ssl_bump: ", err)
            return
        end
    }

    server {
        listen 443 ssl;

        ssl_certificate     /path/to/ca_cert.crt; # 占位
        ssl_certificate_key /path/to/ca_cert.key; # 占位

        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers   on;

        # Dynamic generation of certificates
        ssl_certificate_by_lua_block {
            local ssl_bump = require("resty.ssl_bump")
            ssl_bump.run()
        }

        location / {
            proxy_pass http://your_backend;
        }
    }
}
```

### Importing Your CA Certificate

#### On Linux

To import your CA certificate on Ubuntu:

```
$cp /path/to/ca_cert.crt  /usr/local/share/ca-certificates/ca_cert.crt
# Update CA certificate cache
$update-ca-certificates
```

#### On Windows

To import your CA certificate on Windows:

```
sh
Copy code
certmgr.exe /add %cd%\ca_cert.crt /s /r localMachine root 
```

## License

MIT
