use http_body_util::Full;
use hyper::Response;
use hyper::body::Bytes;

pub fn add_security_headers(mut response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    // Fucking CSP...
    // script-src 'self' 'unsafe-inline'; \
    headers.insert(
        "content-security-policy",
        "default-src 'self'; \
         script-src 'self' \
         'sha256-tnaO7U86+Ftzp1BUcBvWDhfKxxiu8rf2slTl4OIEVhY=' \
         'unsafe-hashes' 'sha256-ZBPx5z6Tpme3l0XdebX/BjM9bT0iVLGV5VrPk4FX5XM='; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' https://avatars.githubusercontent.com; \
         connect-src 'self'; \
         font-src 'self'; \
         object-src 'none'; \
         media-src 'none'; \
         frame-src 'none'; \
         base-uri 'self'; \
         form-action 'self'; \
         frame-ancestors 'none'; \
         upgrade-insecure-requests"
            .parse()
            .unwrap(),
    );

    headers.insert(
        "permissions-policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()"
            .parse()
            .unwrap()
    );

    response
}
