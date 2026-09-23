//! HTTP-level tests against a fake ZAP.
//!
//! The mock engine returns canned structs, so it never exercised the ZAP
//! client itself: URL building, API-key handling, replacer installation, and
//! alert parsing all went untested. These tests stand up a real HTTP server
//! speaking ZAP's API so that layer is covered.

use tsun::severity::Severity;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// A ZAP that is up, has an empty site tree, and finishes scans immediately.
async fn zap_stub() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/JSON/core/view/version/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": "2.15.0"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/JSON/core/action/accessUrl/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessUrl": "OK"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/JSON/replacer/action/addRule/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "addRule": "OK"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/JSON/replacer/action/removeRule/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "removeRule": "OK"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/JSON/ascan/action/scan/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "scan": "42"
        })))
        .mount(&server)
        .await;

    server
}

fn requests_to<'a>(requests: &'a [Request], path: &str) -> Vec<&'a Request> {
    requests
        .iter()
        .filter(|r| r.url.path() == path)
        .collect::<Vec<_>>()
}

#[tokio::test]
async fn auth_headers_are_installed_as_replacer_rules() {
    let server = zap_stub().await;

    let client = tsun::zap::new_real_client_with_headers(
        &server.uri(),
        &[
            ("Authorization".to_string(), "Bearer t0ken".to_string()),
            ("Cookie".to_string(), "SESSION=abc".to_string()),
        ],
        None,
    )
    .expect("client");

    client
        .start_scan("https://target.example.com", None, None, None)
        .await
        .expect("scan should start");

    let requests = server.received_requests().await.unwrap();
    let rules = requests_to(&requests, "/JSON/replacer/action/addRule/");

    assert_eq!(
        rules.len(),
        2,
        "each credential header must become a replacer rule so ZAP sends it to the target"
    );

    let installed: Vec<(String, String)> = rules
        .iter()
        .map(|r| {
            let params: std::collections::HashMap<_, _> =
                r.url.query_pairs().into_owned().collect();
            (
                params.get("matchString").cloned().unwrap_or_default(),
                params.get("replacement").cloned().unwrap_or_default(),
            )
        })
        .collect();

    assert!(installed.contains(&("Authorization".to_string(), "Bearer t0ken".to_string())));
    assert!(installed.contains(&("Cookie".to_string(), "SESSION=abc".to_string())));

    for rule in &rules {
        let params: std::collections::HashMap<_, _> = rule.url.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("matchType").map(String::as_str),
            Some("REQ_HEADER")
        );
        assert_eq!(params.get("enabled").map(String::as_str), Some("true"));
    }
}

#[tokio::test]
async fn credentials_are_not_sent_to_the_zap_api_itself() {
    let server = zap_stub().await;

    let client = tsun::zap::new_real_client_with_headers(
        &server.uri(),
        &[("Authorization".to_string(), "Bearer t0ken".to_string())],
        None,
    )
    .expect("client");

    client
        .start_scan("https://target.example.com", None, None, None)
        .await
        .expect("scan should start");

    let requests = server.received_requests().await.unwrap();
    let scan_requests = requests_to(&requests, "/JSON/ascan/action/scan/");
    assert!(!scan_requests.is_empty());

    for request in scan_requests {
        assert!(
            request.headers.get("authorization").is_none(),
            "target credentials belong in replacer rules, not on our ZAP API calls"
        );
    }
}

#[tokio::test]
async fn no_replacer_rules_are_installed_without_credentials() {
    let server = zap_stub().await;

    let client = tsun::zap::new_real_client_with_headers(&server.uri(), &[], None).expect("client");
    client
        .start_scan("https://target.example.com", None, None, None)
        .await
        .expect("scan should start");

    let requests = server.received_requests().await.unwrap();
    assert!(requests_to(&requests, "/JSON/replacer/action/addRule/").is_empty());
}

#[tokio::test]
async fn api_key_is_attached_to_every_request() {
    let server = zap_stub().await;

    let client =
        tsun::zap::new_real_client_with_headers(&server.uri(), &[], Some("s3cret".to_string()))
            .expect("client");

    client.check_health().await.expect("healthy");
    client
        .start_scan("https://target.example.com", None, None, None)
        .await
        .expect("scan should start");

    let requests = server.received_requests().await.unwrap();
    assert!(!requests.is_empty());

    for request in &requests {
        let params: std::collections::HashMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("apikey").map(String::as_str),
            Some("s3cret"),
            "{} was sent without an API key",
            request.url.path()
        );
    }
}

#[tokio::test]
async fn empty_credential_values_are_skipped() {
    let server = zap_stub().await;

    // An empty cookie file yields an empty Cookie value. Installing a replacer
    // rule for it would strip the header from every request instead.
    let client = tsun::zap::new_real_client_with_headers(
        &server.uri(),
        &[
            ("Cookie".to_string(), "".to_string()),
            ("Authorization".to_string(), "Bearer t0ken".to_string()),
        ],
        None,
    )
    .expect("client");

    client
        .start_scan("https://target.example.com", None, None, None)
        .await
        .expect("scan should start");

    let requests = server.received_requests().await.unwrap();
    let rules = requests_to(&requests, "/JSON/replacer/action/addRule/");

    assert_eq!(
        rules.len(),
        1,
        "only the non-empty header should be installed"
    );
    let params: std::collections::HashMap<_, _> = rules[0].url.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("matchString").map(String::as_str),
        Some("Authorization")
    );
}

#[tokio::test]
async fn missing_replacer_addon_fails_loudly() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/JSON/replacer/action/removeRule/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/JSON/replacer/action/addRule/"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "code": "does_not_exist",
            "message": "Does Not Exist"
        })))
        .mount(&server)
        .await;

    let client = tsun::zap::new_real_client_with_headers(
        &server.uri(),
        &[("Authorization".to_string(), "Bearer t0ken".to_string())],
        None,
    )
    .expect("client");

    let err = client
        .start_scan("https://target.example.com", None, None, None)
        .await
        .expect_err("a scan that cannot authenticate must not silently proceed");

    let message = err.to_string();
    assert!(
        message.contains("Replacer"),
        "error should name the missing add-on, got: {}",
        message
    );
}

#[tokio::test]
async fn health_check_rejects_a_server_that_is_not_zap() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/JSON/core/view/version/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>hello</html>"))
        .mount(&server)
        .await;

    let client = tsun::zap::new_real_client(&server.uri()).expect("client");
    assert!(
        client.check_health().await.is_err(),
        "a 200 from something that is not ZAP is not a healthy ZAP"
    );
}

#[tokio::test]
async fn health_check_reports_http_failure() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/JSON/core/view/version/"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = tsun::zap::new_real_client(&server.uri()).expect("client");
    assert!(client.check_health().await.is_err());
}

#[tokio::test]
async fn rejected_api_key_produces_an_actionable_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/JSON/core/view/version/"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "code": "bad_api_key"
        })))
        .mount(&server)
        .await;

    let client =
        tsun::zap::new_real_client_with_headers(&server.uri(), &[], Some("wrong".to_string()))
            .expect("client");

    let message = client.check_health().await.unwrap_err().to_string();
    assert!(
        message.contains("API key") || message.contains("api key"),
        "error should point at the API key, got: {}",
        message
    );
}

#[tokio::test]
async fn alerts_are_classified_from_risk_and_confidence() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/JSON/core/view/alerts/"))
        .and(query_param("baseurl", "https://target.example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "alerts": [
                {
                    "pluginId": "40018",
                    "alertRef": "40018",
                    "alert": "SQL Injection",
                    "name": "SQL Injection",
                    "url": "https://target.example.com/search?q=1",
                    "risk": "High",
                    "confidence": "Confirmed",
                    "description": "…",
                    "method": "GET",
                    "param": "q",
                    "attack": "' OR 1=1--",
                    "evidence": "SQL syntax"
                },
                {
                    "pluginId": "10015",
                    "alertRef": "10015",
                    "alert": "Server Leaks Version",
                    "name": "Server Leaks Version",
                    "url": "https://target.example.com/",
                    "risk": "Informational",
                    "confidence": "High",
                    "method": "GET"
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = tsun::zap::new_real_client(&server.uri()).expect("client");
    let alerts = client
        .get_alerts("https://target.example.com")
        .await
        .expect("alerts");

    assert_eq!(alerts.len(), 2);

    assert_eq!(alerts[0].severity(), Severity::Critical);
    assert!(alerts[0].cvss_score > 0.0);
    assert!(alerts[0].cvss_estimated);
    assert_eq!(alerts[0].param(), Some("q"));

    assert_eq!(
        alerts[1].severity(),
        Severity::Info,
        "informational must not be reported as Low"
    );
}

#[tokio::test]
async fn alert_parsing_tolerates_schema_drift() {
    let server = MockServer::start().await;

    // Lowercase `pluginid`, numeric risk, and several fields simply absent —
    // all shapes seen across ZAP versions and add-ons.
    Mock::given(method("GET"))
        .and(path("/JSON/core/view/alerts/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "alerts": [
                {
                    "pluginid": "10038",
                    "alert": "CSP Header Not Set",
                    "name": "CSP Header Not Set",
                    "url": "https://target.example.com/",
                    "riskcode": "3"
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = tsun::zap::new_real_client(&server.uri()).expect("client");
    let alerts = client
        .get_alerts("https://target.example.com")
        .await
        .expect("drifted schema should still parse");

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].pluginid, "10038");
    // On ZAP's numeric scale "3" is High; confidence is absent, which defaults
    // to Medium and so does not promote to Critical.
    assert_eq!(alerts[0].severity(), Severity::High);
}

#[tokio::test]
async fn scan_parameters_reach_the_zap_api() {
    let server = zap_stub().await;

    let client = tsun::zap::new_real_client(&server.uri()).expect("client");
    client
        .start_scan(
            "https://target.example.com",
            Some(150),
            Some("high"),
            Some("low"),
        )
        .await
        .expect("scan should start");

    let requests = server.received_requests().await.unwrap();
    let scan = requests_to(&requests, "/JSON/ascan/action/scan/")[0];
    let params: std::collections::HashMap<_, _> = scan.url.query_pairs().into_owned().collect();

    assert_eq!(
        params.get("url").map(String::as_str),
        Some("https://target.example.com")
    );
    assert_eq!(params.get("maxChildren").map(String::as_str), Some("150"));
    assert_eq!(
        params.get("attackStrength").map(String::as_str),
        Some("HIGH")
    );
    assert_eq!(
        params.get("alertThreshold").map(String::as_str),
        Some("LOW")
    );
}
