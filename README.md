# JavasScript proxy
Launch a HTTP(s) proxy using only a browser on the proxying machine. You must control the browser enough to disable CORS.
This can be used as a hackish workaround when you are not able to run your mitm-proxy such as burp or zap on the target system/network or if there are certificates that only the browser can access for some reason.

Note. Must use chrome/edge `--disable-web-security` flag, otherwise you are blocked by CORS. (On some systems file:// may work)

# Security
- This uses http.server which is not considered secure for production. 
- There is no auth nor verification of clients.
- Input validation has not been reviewed
- In fact, nothing has been reviewed, but it seems to work at least.
- `--disable-web-security` also applies to all your visited pages through the proxy, so any issues you discover could be blocked by CORS. Also, don't visit anything you don't trust.

# Usage examples
### 1. Run Proxy (on your lab machine):
`python3 proxy.py --publicaddr 192.168.1.30 --pport 8080 --wport 8000`

### 2. Start local browser (on the machine with certs/network access)
`chromium --disable-web-security --user-data-dir=/tmp/ "file://$(pwd)/proxy.html"`

(Windows)

`start chrome --ArgumentList "--disable-web-security","--user-data-dir=$env:LOCALAPPDATA\\Temp","""file://$(pwd)/proxy.html"""`

alt.

`start msedge --ArgumentList "--disable-web-security","--user-data-dir=$env:LOCALAPPDATA\\Temp","""http://192.168.1.30:8000/proxy"""`


### 3. Make request:
`https_proxy=http://localhost:8080 curl -k https://google.com/`

# What happens 
1. curl connects to port 8000 in proxy.py
2. proxy.py sends the request details to proxy.html running in browser
3. proxy.html performs the request.
4. proxy.html returns the response to proxy.py 
5. proxy.py returns the response to curl.

# Limitations
- The browser makes the requests, so it is not guaranteed that all headers are sent exactly as your client. Most notably fetch() doesn't allow us to set cookies, and some other headers: https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name
- Similarly the response is not guaranteed to be exactly what was returned - for example the Content-Encoding and Content-Length will be changed.
- You cannot run this on a website as you will be blocked by CORS (Unless the visitor launched their browser with `--disable-web-security`).
- Only test Firefox needs additional config to disable CORS
- All CONNECT attempts are MITMd, only HTTP(s) allowed.

