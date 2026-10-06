wrk.method = "POST"
wrk.body = string.rep("a", 65536)
wrk.headers["Content-Type"] = "application/octet-stream"
