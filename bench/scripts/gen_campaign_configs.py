#!/usr/bin/env python3
"""Generate the campaign bench configs into bench/<dir>/ (run from repo root)."""
import os

PRE = """# {title}
# Generated for the 0.1.2 performance campaign; parsed by both nginx and ruxen.
# Run (from repo root): nginx -p "$PWD/bench/{d}/" -c nginx.conf

worker_processes  auto;
worker_rlimit_nofile 1048576;

error_log  /tmp/ruxen-bench-{d}-error.log  crit;
pid        /tmp/ruxen-bench-{d}.pid;

events {{
    worker_connections  4096;
    use                 epoll;
    multi_accept        on;
}}

http {{
    access_log           off;
    default_type         text/plain;
    sendfile             on;
    tcp_nopush           on;
    tcp_nodelay          on;

    keepalive_timeout    65;
    keepalive_requests   1000000;
"""


def write(d, title, body):
    os.makedirs(f"bench/{d}", exist_ok=True)
    with open(f"bench/{d}/nginx.conf", "w") as f:
        f.write(PRE.format(title=title, d=d) + body + "}\n")


def gen_sh(d, lines):
    p = f"bench/{d}/generate.sh"
    with open(p, "w") as f:
        f.write("#!/usr/bin/env bash\n# Fixtures for this bench config (git-ignored).\nset -euo pipefail\ncd \"$(dirname \"$0\")\"\n")
        f.write("\n".join(lines) + "\n")
    os.chmod(p, 0o755)


FILE = 'f() { [ "$(stat -c %s "$1" 2>/dev/null)" = "$2" ] || head -c "$2" /dev/urandom > "$1"; }'

# --- core2: request processing without files -------------------------------
maprx = "\n".join(f"        ~^/maprx/k{i}$ v{i};" for i in range(50))
write("core2", "Request-processing paths without files: redirects, variables, set/if, split_clients, map regexes, captures, named error pages.", f"""
    map $uri $mapped {{
        default none;
{maprx}
    }}

    split_clients "${{remote_addr}}${{request_uri}}" $variant {{
        50%     a;
        30%     b;
        *       c;
    }}

    server {{
        listen 8110 reuseport backlog=4096;
        server_name _;

        location = /hello {{
            return 200 "hello";
        }}
        location = /redirect {{
            return 301 https://example.com$request_uri;
        }}
        location = /vars {{
            return 200 "$remote_addr $request_uri $http_host $server_name $scheme $request_method $uri $args\\n";
        }}
        location = /args {{
            return 200 "$arg_x $arg_y";
        }}
        location = /setif {{
            set $a "x";
            if ($http_x_test ~* "^yes") {{
                set $a "${{a}}y";
            }}
            if ($arg_z != "1") {{
                set $a "${{a}}z";
            }}
            return 200 $a;
        }}
        location = /split {{
            return 200 $variant;
        }}
        location /maprx/ {{
            return 200 $mapped;
        }}
        location = /hdrvars {{
            add_header X-Host $host;
            add_header X-Uri $uri;
            add_header X-Method $request_method;
            add_header X-Addr $remote_addr;
            return 200 "hello";
        }}
        location /rc/ {{
            rewrite ^/rc/(\\d+)/(\\w+)$ /rct?id=$1&n=$2 last;
        }}
        location = /rct {{
            return 200 "$arg_id $arg_n";
        }}
        location = /errnamed {{
            error_page 404 = @fallback;
            return 404;
        }}
        location @fallback {{
            return 200 "fallback";
        }}
    }}
""")

# --- locations ---------------------------------------------------------------
regex = "\n".join(f"        location ~ ^/re{i}/ {{\n            return 200 \"re{i}\";\n        }}" for i in range(50))
prefix = "\n".join(f"        location /p{i}/ {{\n            return 200 \"p{i}\";\n        }}" for i in range(200))
write("locations", "Location matching: 50 regex locations (the request matches the last one) and 200 prefix locations.", f"""
    server {{
        listen 8130 reuseport backlog=4096;
        server_name _;

        location / {{
            return 200 "root";
        }}
{regex}
    }}

    server {{
        listen 8131 reuseport backlog=4096;
        server_name _;

        location / {{
            return 200 "root";
        }}
{prefix}
    }}
""")

# --- vhosts --------------------------------------------------------------------
v = ["""
    server {
        listen 8132 reuseport backlog=4096 default_server;
        server_name _;
        return 200 "default";
    }
"""]
for i in range(100):
    v.append(f"    server {{\n        listen 8132;\n        server_name h{i}.example.com;\n        return 200 \"h{i}\";\n    }}\n")
for i in range(50):
    v.append(f"    server {{\n        listen 8132;\n        server_name *.w{i}.example.com;\n        return 200 \"w{i}\";\n    }}\n")
for i in range(20):
    v.append(f"    server {{\n        listen 8132;\n        server_name ~^r{i}-(\\w+)\\.example\\.org$;\n        return 200 \"r{i}\";\n    }}\n")
write("vhosts", "Virtual-host selection: 100 exact, 50 wildcard and 20 regex server names on one port.", "".join(v))

# --- static2 --------------------------------------------------------------------
write("static2", "Static files: sizes from 0 B to 256 KiB, sendfile off, index, try_files hit and fallback, alias, expires, autoindex.", """
    server {
        listen 8133 reuseport backlog=4096;
        server_name _;
        root html;

        location /nosf/ {
            sendfile off;
        }
        location /spa/ {
            try_files $uri /spa/index.html;
        }
        location /a/ {
            alias html/alias-src/;
        }
        location /exp/ {
            expires 1h;
        }
        location /list/ {
            autoindex on;
        }
    }
""")
gen_sh("static2", [FILE,
    "mkdir -p html/nosf html/dir html/spa html/alias-src html/exp html/list",
    ": > html/0.txt",
    "f html/hello1k.txt 1024; f html/16k.bin 16384; f html/64k.bin 65536; f html/256k.bin 262144",
    "f html/nosf/hello1k.txt 1024; f html/nosf/1M.bin 1048576",
    "f html/dir/index.html 1024",
    "f html/spa/index.html 1024; f html/spa/app.js 1024",
    "f html/alias-src/hello1k.txt 1024",
    "f html/exp/hello1k.txt 1024",
    "for i in $(seq -w 0 99); do f html/list/file-$i.txt 100; done",
])

# --- logging --------------------------------------------------------------------
write("logging", "Access logging in the combined format, written to /dev/null (formatting and the write syscall, without filling a disk).", """
    server {
        listen 8134 reuseport backlog=4096;
        server_name _;
        root html;
        access_log /dev/null combined;

        location = / {
            return 200 "hello";
        }
        location / {
        }
    }
""")
gen_sh("logging", [FILE, "mkdir -p html", "f html/hello1k.txt 1024"])

# --- body --------------------------------------------------------------------
write("body", "Request bodies: POST discarded by a return, and POST forwarded to an upstream with keep-alive (nginx's default 16k client_body_buffer_size; larger bodies go to client_body_temp_path).", """
    client_body_temp_path /tmp/ruxen-bench-body-temp;
    proxy_temp_path       /tmp/ruxen-bench-proxy-temp;
    upstream bodyup {
        server 127.0.0.1:18135;
        keepalive 64;
    }

    server {
        listen 8135 reuseport backlog=4096;
        server_name _;

        location = /sink {
            return 200 "ok";
        }
        location = /proxy {
            proxy_pass http://bodyup;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }

    server {
        listen 18135 reuseport backlog=4096;
        server_name _;

        location / {
            return 200 "ok";
        }
    }
""")
for n, size in (("post_1k", 1024), ("post_64k", 65536)):
    with open(f"bench/body/{n}.lua", "w") as f:
        f.write(f'wrk.method = "POST"\nwrk.body = string.rep("a", {size})\nwrk.headers["Content-Type"] = "application/octet-stream"\n')

# --- proxy2 --------------------------------------------------------------------
pool = "\n".join(f"        server 127.0.0.1:{p};" for p in range(18141, 18145))
ups = "\n".join(f"""    server {{
        listen {p} reuseport backlog=4096;
        server_name _;
        return 200 "hello";
    }}
""" for p in (18140, 18141, 18142, 18143, 18144))
KA = """            proxy_http_version 1.1;
            proxy_set_header Connection "";"""
write("proxy2", "Reverse-proxy variants: no upstream keep-alive, round robin and least_conn over 4 servers, proxy_set_header with variables, 64 KiB and 1 MiB responses, intercepted errors, client without keep-alive, proxy_redirect, X-Accel-Redirect.", f"""
    proxy_temp_path      /tmp/ruxen-bench-proxy-temp;

    upstream pool_rr {{
{pool}
        keepalive 64;
    }}

    upstream pool_lc {{
        least_conn;
{pool}
        keepalive 64;
    }}

    upstream files {{
        server 127.0.0.1:18150;
        keepalive 64;
    }}

    upstream misc {{
        server 127.0.0.1:18151;
        keepalive 64;
    }}

    server {{
        listen 8140 reuseport backlog=4096;
        server_name _;
        location / {{
            proxy_pass http://127.0.0.1:18140;
        }}
    }}

    server {{
        listen 8141 reuseport backlog=4096;
        server_name _;
        location / {{
            proxy_pass http://pool_rr;
{KA}
        }}
    }}

    server {{
        listen 8142 reuseport backlog=4096;
        server_name _;
        location / {{
            proxy_pass http://pool_lc;
{KA}
        }}
    }}

    server {{
        listen 8143 reuseport backlog=4096;
        server_name _;
        location / {{
            proxy_pass http://pool_rr;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Request-Uri $request_uri;
        }}
    }}

    server {{
        listen 8144 reuseport backlog=4096;
        server_name _;
        root html;
        location / {{
            proxy_pass http://files;
{KA}
        }}
        location = /intercept {{
            proxy_pass http://misc;
{KA}
            proxy_intercept_errors on;
            error_page 404 = /fallback;
        }}
        location = /fallback {{
            return 200 "fallback";
        }}
        location = /redirect {{
            proxy_pass http://misc;
{KA}
        }}
        location = /xar {{
            proxy_pass http://misc;
{KA}
        }}
        location /internal/ {{
            internal;
        }}
    }}

    server {{
        listen 8147 reuseport backlog=4096;
        server_name _;
        keepalive_timeout 0;
        location / {{
            proxy_pass http://pool_rr;
{KA}
        }}
    }}

{ups}
    server {{
        listen 18150 reuseport backlog=4096;
        server_name _;
        root html;
    }}

    server {{
        listen 18151 reuseport backlog=4096;
        server_name _;
        location = /intercept {{
            return 404;
        }}
        location = /redirect {{
            return 302 http://127.0.0.1:18151/next;
        }}
        location = /xar {{
            add_header X-Accel-Redirect /internal/hello1k.txt;
            return 200 "";
        }}
    }}
""")
gen_sh("proxy2", [FILE, "mkdir -p html/internal", "f html/64k.bin 65536; f html/1M.bin 1048576; f html/internal/hello1k.txt 1024"])

# --- tls2 --------------------------------------------------------------------
TLS = """        ssl_certificate     /tmp/ruxen-bench-tls/cert.pem;
        ssl_certificate_key /tmp/ruxen-bench-tls/key.pem;"""
RSA = """        ssl_certificate     /tmp/ruxen-bench-tls/rsa-cert.pem;
        ssl_certificate_key /tmp/ruxen-bench-tls/rsa-key.pem;"""
write("tls2", "TLS variants: TLS 1.2, full handshakes per request (1.3, 1.2, RSA 2048), static files and a reverse proxy behind TLS.", f"""
    ssl_session_cache    shared:bench:10m;
    ssl_session_tickets  on;

    upstream plain {{
        server 127.0.0.1:18455;
        keepalive 64;
    }}

    server {{
        listen 8450 ssl reuseport backlog=4096;
        server_name _;
        ssl_protocols TLSv1.2;
{TLS}
        location / {{
            return 200 "hello";
        }}
    }}

    server {{
        listen 8451 ssl reuseport backlog=4096;
        server_name _;
        ssl_protocols TLSv1.3;
        keepalive_timeout 0;
{TLS}
        location / {{
            return 200 "hello";
        }}
    }}

    server {{
        listen 8452 ssl reuseport backlog=4096;
        server_name _;
        ssl_protocols TLSv1.2;
        keepalive_timeout 0;
{TLS}
        location / {{
            return 200 "hello";
        }}
    }}

    server {{
        listen 8453 ssl reuseport backlog=4096;
        server_name _;
        ssl_protocols TLSv1.3;
        keepalive_timeout 0;
{RSA}
        location / {{
            return 200 "hello";
        }}
    }}

    server {{
        listen 8454 ssl reuseport backlog=4096;
        server_name _;
        ssl_protocols TLSv1.3;
        root html;
{TLS}
    }}

    server {{
        listen 8455 ssl reuseport backlog=4096;
        server_name _;
        ssl_protocols TLSv1.3;
{TLS}
        location / {{
            proxy_pass http://plain;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}

    server {{
        listen 18455 reuseport backlog=4096;
        server_name _;
        return 200 "hello";
    }}
""")
gen_sh("tls2", [FILE, '../tls/generate.sh >/dev/null',
    'd=/tmp/ruxen-bench-tls',
    '[ -s $d/rsa-key.pem ] || openssl req -x509 -nodes -newkey rsa:2048 -keyout $d/rsa-key.pem -out $d/rsa-cert.pem -days 365 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1',
    "mkdir -p html", "f html/hello1k.txt 1024; f html/1M.bin 1048576"])
print("ok")

# --- proxy_ext: frontends in front of one external nginx backend ----------------
KA2 = """            proxy_http_version 1.1;
            proxy_set_header Connection "";"""
write("proxy_ext", "Proxy frontends in front of a separate nginx backend (bench/proxy_ext/backend.conf, started once for the whole phase), so both servers under test are measured as proxies only.", f"""
    client_body_temp_path /tmp/ruxen-bench-body-temp;
    proxy_temp_path       /tmp/ruxen-bench-proxy-temp;

    upstream ext {{
        server 127.0.0.1:19140;
        keepalive 64;
    }}

    upstream extfiles {{
        server 127.0.0.1:19141;
        keepalive 64;
    }}

    upstream extmisc {{
        server 127.0.0.1:19142;
        keepalive 64;
    }}

    server {{
        listen 8160 reuseport backlog=4096;
        server_name _;
        root html;

        location / {{
            proxy_pass http://ext;
{KA2}
        }}
        location = /direct {{
            proxy_pass http://127.0.0.1:19140;
        }}
        location /files/ {{
            proxy_pass http://extfiles;
{KA2}
        }}
        location = /xar {{
            proxy_pass http://extmisc;
{KA2}
        }}
        location /internal/ {{
            internal;
        }}
    }}
""")
with open("bench/proxy_ext/backend.conf", "w") as f:
    f.write("""# Backend for bench/proxy_ext: a plain nginx, started once for the phase:
#   nginx -p "$PWD/bench/proxy_ext/" -c "$PWD/bench/proxy_ext/backend.conf"
worker_processes  4;
worker_rlimit_nofile 1048576;
error_log  /tmp/ruxen-bench-proxy_ext-backend-error.log  crit;
pid        /tmp/ruxen-bench-proxy_ext-backend.pid;
events {
    worker_connections  4096;
    use                 epoll;
    multi_accept        on;
}
http {
    access_log           off;
    default_type         text/plain;
    sendfile             on;
    tcp_nopush           on;
    tcp_nodelay          on;
    keepalive_timeout    65;
    keepalive_requests   1000000;
    client_body_temp_path /tmp/ruxen-bench-backend-body-temp;

    server {
        listen 19140 reuseport backlog=4096;
        return 200 "hello";
    }
    server {
        listen 19141 reuseport backlog=4096;
        root html;
    }
    server {
        listen 19142 reuseport backlog=4096;
        location = /xar {
            add_header X-Accel-Redirect /internal/hello1k.txt;
            return 200 "";
        }
    }
}
""")
gen_sh("proxy_ext", [FILE, "mkdir -p html/files html/internal", "f html/files/64k.bin 65536; f html/files/1M.bin 1048576; f html/internal/hello1k.txt 1024"])
