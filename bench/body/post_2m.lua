wrk.method = "POST"
wrk.body = string.rep("a", 2097152)
wrk.headers["Content-Type"] = "application/octet-stream"
