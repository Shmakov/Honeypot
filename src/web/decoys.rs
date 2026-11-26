//! Realistic HTTP decoy traps for high-value attacker probes.
//! Unknown paths not matching a decoy fall through to Request Echo.

use axum::http::StatusCode;

/// Check whether a path is a secret/canary trap path.
pub fn is_canary_path(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path).to_ascii_lowercase();
    matches!(
        p.as_str(),
        "/.env" | "/.env.production" | "/.env.local" | "/config/.env" | "/actuator/env"
    )
}

/// Match an incoming request against realistic decoy traps.
/// Returns `(StatusCode, Content-Type, body, optional_extra_tag)`.
pub fn match_decoy(
    method: &str,
    path: &str,
    _body: Option<&[u8]>,
) -> Option<(StatusCode, &'static str, String, Option<&'static str>)> {
    let p = path.split('?').next().unwrap_or(path).to_ascii_lowercase();

    match p.as_str() {
        "/.env" | "/.env.production" | "/.env.local" | "/config/.env" => Some((
            StatusCode::OK,
            "text/plain; charset=utf-8",
            "APP_NAME=Portal\n\
             APP_ENV=production\n\
             APP_DEBUG=false\n\
             APP_KEY=base64:dGhpc2lzYWRlY295aG9uZXlwb3RrZXkyMDI2PT0=\n\
             DB_CONNECTION=mysql\n\
             DB_HOST=10.0.4.18\n\
             DB_PORT=3306\n\
             DB_DATABASE=portal_prod\n\
             DB_USERNAME=portal_app\n\
             DB_PASSWORD=DecoyDbPassword#2026\n\
             AWS_ACCESS_KEY_ID=AKIAIOSFODNN7HONEY01\n\
             AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYKEY\n\
             STRIPE_SECRET_KEY=sk_live_honeypot_decoy_0000000000000000\n"
                .to_string(),
            Some("canary-triggered"),
        )),
        "/actuator/env" => Some((
            StatusCode::OK,
            "application/json",
            r#"{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig","properties":{"spring.datasource.password":{"value":"DecoySpringPass#2026"},"aws.secretKey":{"value":"AKIAIOSFODNN7HONEY01"}}}]}"#
                .to_string(),
            Some("canary-triggered"),
        )),
        "/actuator/health" => Some((
            StatusCode::OK,
            "application/json",
            r#"{"status":"UP","components":{"db":{"status":"UP"},"diskSpace":{"status":"UP"}}}"#
                .to_string(),
            None,
        )),
        "/wp-login.php" => {
            if method.eq_ignore_ascii_case("POST") {
                Some((
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    r#"<!DOCTYPE html><html><head><title>Log In &lsaquo; Site &#8212; WordPress</title></head><body><div id="login"><div id="login_error"><strong>Error:</strong> The password you entered for the username is incorrect.</div><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" /></p><p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" /></p><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p></form></div></body></html>"#
                        .to_string(),
                    Some("wp-probe"),
                ))
            } else {
                Some((
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    r#"<!DOCTYPE html><html><head><title>Log In &lsaquo; Site &#8212; WordPress</title><meta name="generator" content="WordPress 6.4.3" /></head><body><div id="login"><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" /></p><p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" /></p><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p></form></div></body></html>"#
                        .to_string(),
                    Some("wp-probe"),
                ))
            }
        }
        "/xmlrpc.php" => Some((
            StatusCode::OK,
            "text/xml; charset=utf-8",
            r#"<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>-32700</int></value></member><member><name>faultString</name><value><string>parse error. not well formed</string></value></member></struct></value></fault></methodResponse>"#
                .to_string(),
            Some("wp-probe"),
        )),
        "/phpmyadmin" | "/phpmyadmin/" | "/phpmyadmin/index.php" | "/pma" | "/pma/" => Some((
            StatusCode::OK,
            "text/html; charset=utf-8",
            r#"<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body><h1>Welcome to phpMyAdmin</h1><form method="post" action="/phpmyadmin/index.php"><label>Username: <input type="text" name="pma_username" /></label><label>Password: <input type="password" name="pma_password" /></label><input type="submit" value="Go" /></form></body></html>"#
                .to_string(),
            Some("admin-probe"),
        )),
        "/boaform/admin/formlogin" | "/hnap1/" => Some((
            StatusCode::OK,
            "text/html; charset=utf-8",
            r#"<!DOCTYPE html><html><head><title>Router Administration</title></head><body><form method="post" action="/boaform/admin/formLogin"><input name="username" /><input type="password" name="psd" /><input type="submit" value="Login" /></form></body></html>"#
                .to_string(),
            Some("mirai-iot"),
        )),
        "/api/tags" | "/v1/models" => Some((
            StatusCode::OK,
            "application/json",
            r#"{"models":[{"name":"llama3.2:latest","size":2019393189},{"name":"qwen2.5-coder:7b","size":4683087332}]}"#
                .to_string(),
            Some("llm-probe"),
        )),
        _ => None,
    }
}
