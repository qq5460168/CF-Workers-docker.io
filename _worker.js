// _worker.js

// Docker registry upstream hosts
const DEFAULT_HUB_HOST = 'registry-1.docker.io';
const AUTH_URL = 'https://auth.docker.io';
const ROUTE_MAP = {
    quay: 'quay.io',
    gcr: 'gcr.io',
    'k8s-gcr': 'k8s.gcr.io',
    k8s: 'registry.k8s.io',
    ghcr: 'ghcr.io',
    cloudsmith: 'docker.cloudsmith.io',
    nvcr: 'nvcr.io',
    test: 'registry-1.docker.io',
};
// Default block user agents
const DEFAULT_BLOCK_UA = ['netcraft'];

const PREFLIGHT_INIT = {
    headers: new Headers({
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
        'access-control-max-age': '1728000',
    }),
};

// Cache static HTML in global scope
let cachedNginxHTML = null;
let cachedSearchHTML = null;

// Utility: Make a Response with CORS
function makeRes(body, status = 200, headers = {}) {
    headers['access-control-allow-origin'] = '*';
    return new Response(body, { status, headers });
}

// Utility: Safe new URL
function newUrl(urlStr, base) {
    try {
        return new URL(urlStr, base);
    } catch (err) {
        console.error(err);
        return null;
    }
}

// Nginx fake page (cached)
async function nginxPage() {
    if (!cachedNginxHTML) {
        cachedNginxHTML = `
        <!DOCTYPE html>
        <html>
        <head>
        <title>Welcome to nginx!</title>
        <style>
            body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
        </style>
        </head>
        <body>
        <h1>Welcome to nginx!</h1>
        <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
        <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
        Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
        <p><em>Thank you for using nginx.</em></p>
        </body>
        </html>
        `;
    }
    return cachedNginxHTML;
}

// Docker search page (cached)
async function searchInterfacePage() {
    if (!cachedSearchHTML) {
        cachedSearchHTML = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Docker Hub 镜像搜索</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <!-- ...省略style... -->
        </head>
        <body>
            <!-- ...省略body内容... -->
        </body>
        </html>
        `;
    }
    return cachedSearchHTML;
}

// Route host
function routeByHosts(host) {
    if (host in ROUTE_MAP) return [ROUTE_MAP[host], false];
    return [DEFAULT_HUB_HOST, true];
}

// Add extra UA
async function mergeBlockUA(envUA) {
    if (!envUA) return DEFAULT_BLOCK_UA;
    let addText = envUA.replace(/[ \t|"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (addText.startsWith(',')) addText = addText.slice(1);
    if (addText.endsWith(',')) addText = addText.slice(0, -1);
    return DEFAULT_BLOCK_UA.concat(addText.split(','));
}

// Main fetch handler
export default {
    async fetch(request, env, ctx) {
        try {
            // CORS preflight
            if (request.method === 'OPTIONS') {
                return new Response(null, PREFLIGHT_INIT);
            }

            let blockUserAgents = DEFAULT_BLOCK_UA;
            if (env.UA) blockUserAgents = await mergeBlockUA(env.UA);

            const url = new URL(request.url);
            const userAgentHeader = request.headers.get('User-Agent');
            const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : 'null';
            const workersUrl = `https://${url.hostname}`;

            // Validate "ns" parameter (protect from injection)
            const ns = url.searchParams.get('ns');
            if (ns && !/^[a-z0-9.\-]+$/.test(ns)) {
                return makeRes('Invalid ns param', 400, { 'content-type': 'text/plain' });
            }
            const hostname = url.searchParams.get('hubhost') || url.hostname;
            const hostTop = hostname.split('.')[0].toLowerCase();

            // Determine upstream host
            let hubHost = DEFAULT_HUB_HOST;
            let fakePage = false;
            if (ns) {
                if (ns === 'docker.io') hubHost = 'registry-1.docker.io';
                else hubHost = ns;
            } else {
                const [routeHost, isFake] = routeByHosts(hostTop);
                hubHost = routeHost;
                fakePage = isFake;
            }

            // Block specified UA
            if (blockUserAgents.some(ua => userAgent.includes(ua))) {
                return new Response(await nginxPage(), {
                    headers: {
                        'Content-Type': 'text/html; charset=UTF-8',
                        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline';"
                    }
                });
            }

            // Home or search UI logic
            const hubParams = ['/v1/search', '/v1/repositories'];
            if ((userAgent && userAgent.includes('mozilla')) || hubParams.some(param => url.pathname.includes(param))) {
                if (url.pathname === '/') {
                    if (env.URL302) {
                        return Response.redirect(env.URL302, 302);
                    } else if (env.URL) {
                        if (env.URL.toLowerCase() === 'nginx') {
                            return new Response(await nginxPage(), {
                                headers: {
                                    'Content-Type': 'text/html; charset=UTF-8',
                                    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline';"
                                }
                            });
                        } else {
                            return fetch(new Request(env.URL, request));
                        }
                    } else if (fakePage) {
                        return new Response(await searchInterfacePage(), {
                            headers: {
                                'Content-Type': 'text/html; charset=UTF-8',
                                'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline';"
                            }
                        });
                    }
                } else {
                    if (fakePage) url.hostname = 'hub.docker.com';
                    if (url.searchParams.get('q')?.includes('library/') && url.searchParams.get('q') !== 'library/') {
                        const search = url.searchParams.get('q');
                        url.searchParams.set('q', search.replace('library/', ''));
                    }
                    return fetch(new Request(url, request));
                }
            }

            // Fix encoded requests
            if (!/%2F/.test(url.search) && /%3A/.test(url.toString())) {
                let modifiedUrl = url.toString().replace(/%3A(?=.*?&)/, '%3Alibrary%2F');
                url = new URL(modifiedUrl);
            }

            // Token requests
            if (url.pathname.includes('/token')) {
                const tokenHeaders = {
                    'Host': 'auth.docker.io',
                    'User-Agent': userAgentHeader,
                    'Accept': request.headers.get('Accept'),
                    'Accept-Language': request.headers.get('Accept-Language'),
                    'Accept-Encoding': request.headers.get('Accept-Encoding'),
                    'Connection': 'keep-alive',
                    'Cache-Control': 'max-age=0'
                };
                const tokenUrl = AUTH_URL + url.pathname + url.search;
                return fetch(new Request(tokenUrl, request), { headers: tokenHeaders });
            }

            // /v2/ path fix for docker.io
            if (hubHost === 'registry-1.docker.io' && /^\/v2\/[^/]+\/[^/]+\/[^/]+$/.test(url.pathname) && !/^\/v2\/library/.test(url.pathname)) {
                url.pathname = '/v2/library/' + url.pathname.split('/v2/')[1];
            }

            // Build fetch parameters
            const fetchHeaders = {
                'Host': hubHost,
                'User-Agent': userAgentHeader,
                'Accept': request.headers.get('Accept'),
                'Accept-Language': request.headers.get('Accept-Language'),
                'Accept-Encoding': request.headers.get('Accept-Encoding'),
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0'
            };
            if (request.headers.has('Authorization')) {
                fetchHeaders['Authorization'] = request.headers.get('Authorization');
            }
            if (request.headers.has('X-Amz-Content-Sha256')) {
                fetchHeaders['X-Amz-Content-Sha256'] = request.headers.get('X-Amz-Content-Sha256');
            }
            const fetchOptions = {
                headers: fetchHeaders,
                cacheTtl: 3600
            };

            // Proxy main request
            let originResponse = await fetch(new Request(url, request), fetchOptions);
            let originHeaders = new Headers(originResponse.headers);
            let status = originResponse.status;

            // Patch Www-Authenticate header
            if (originHeaders.get("Www-Authenticate")) {
                const auth = originHeaders.get("Www-Authenticate");
                const re = new RegExp(AUTH_URL, 'g');
                originHeaders.set("Www-Authenticate", auth.replace(re, workersUrl));
            }
            // Patch Location header (redirect)
            if (originHeaders.get("Location")) {
                const location = originHeaders.get("Location");
                return httpHandler(request, location, hubHost);
            }

            // Patch CORS and cache-control
            originHeaders.set('access-control-expose-headers', '*');
            originHeaders.set('access-control-allow-origin', '*');
            originHeaders.set('Cache-Control', 'max-age=1500');
            // Remove potentially unsafe headers
            ['content-security-policy', 'content-security-policy-report-only', 'clear-site-data'].forEach(h => originHeaders.delete(h));

            return new Response(originResponse.body, {
                status,
                headers: originHeaders
            });
        } catch (err) {
            return makeRes('Internal Server Error', 500, { 'content-type': 'text/plain' });
        }
    }
};

// HTTP handler for redirects
function httpHandler(req, location, baseHost) {
    const reqHeaders = new Headers(req.headers);
    reqHeaders.delete("Authorization");
    const urlObj = newUrl(location, 'https://' + baseHost);
    const reqInit = {
        method: req.method,
        headers: reqHeaders,
        redirect: 'follow',
        body: req.body
    };
    return proxy(urlObj, reqInit, '');
}

// Proxy handler for external requests
async function proxy(urlObj, reqInit, rawLen) {
    const res = await fetch(urlObj.href, reqInit);
    const resHdrOld = res.headers;
    const resHdrNew = new Headers(resHdrOld);

    if (rawLen) {
        const newLen = resHdrOld.get('content-length') || '';
        if (rawLen !== newLen) {
            return makeRes(res.body, 400, {
                '--error': `bad len: ${newLen}, except: ${rawLen}`,
                'access-control-expose-headers': '--error',
            });
        }
    }
    const status = res.status;
    resHdrNew.set('access-control-expose-headers', '*');
    resHdrNew.set('access-control-allow-origin', '*');
    resHdrNew.set('Cache-Control', 'max-age=1500');
    ['content-security-policy', 'content-security-policy-report-only', 'clear-site-data'].forEach(h => resHdrNew.delete(h));

    return new Response(res.body, {
        status,
        headers: resHdrNew
    });
}
