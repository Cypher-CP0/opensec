#!/usr/bin/env python3
"""A curl-shaped client for the isolated workspace's controlled HTTP broker."""
import base64
import json
import socket
import sys

def main():
    args = sys.argv[1:]
    method, headers, body, output = "GET", {}, "", None
    url = None
    include = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "-o", "--output"):
            i += 1
            if i >= len(args):
                raise ValueError("missing argument")
            value = args[i]
            if arg in ("-X", "--request"):
                method = value.upper()
            elif arg in ("-H", "--header"):
                if ":" not in value:
                    raise ValueError("invalid header")
                name, data = value.split(":", 1)
                headers[name.strip()] = data.strip()
            elif arg in ("-d", "--data", "--data-raw"):
                method, body = "POST" if method == "GET" else method, value
            else:
                output = value
        elif arg in ("-I", "--head"):
            method = "HEAD"
        elif arg in ("-i", "--include"):
            include = True
        elif arg in ("-s", "-S", "-sS", "--silent", "--show-error"):
            pass
        elif arg == "--json":
            i += 1
            if i >= len(args):
                raise ValueError("missing JSON")
            method, body = "POST" if method == "GET" else method, args[i]
            headers["Content-Type"] = "application/json"
        elif arg.startswith(("http://", "https://")) and url is None:
            url = arg
        else:
            raise ValueError("unsupported argument: " + arg)
        i += 1
    if url is None:
        raise ValueError("URL is required")
    raw = json.dumps({"url": url, "method": method, "headers": headers, "body": body}).encode()
    if len(raw) > 65536:
        raise ValueError("request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(40)
        client.connect("/tmp/opensec-http.sock")
        client.sendall(raw + b"\n")
        data = bytearray()
        while b"\n" not in data:
            chunk = client.recv(65536)
            if not chunk or len(data) + len(chunk) > 262144:
                raise ValueError("invalid broker response")
            data.extend(chunk)
    result = json.loads(bytes(data).split(b"\n", 1)[0])
    if result.get("error"):
        raise ValueError(result["error"])
    content = base64.b64decode(result.get("body_base64", ""), validate=True)
    if include:
        sys.stdout.write("HTTP/1.1 " + str(result["status"]) + "\n")
        for name, value in result.get("headers", {}).items():
            sys.stdout.write(name + ": " + value + "\n")
        sys.stdout.write("\n")
    if output is None:
        sys.stdout.buffer.write(content)
    else:
        if not output.startswith("/work/") or ".." in output.split("/"):
            raise ValueError("output must stay under /work")
        with open(output, "wb") as file:
            file.write(content)

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        print("opensec-http: " + str(error), file=sys.stderr)
        sys.exit(2)
