//! App-info + update-check + safe URL opener.
//!
//! Tiny module: just enough to render the About panel and let the user
//! see whether a newer release exists on GitHub. The actual download
//! is intentionally NOT automated — we surface the release URL and let
//! the user pick whether to grab it (auto-update infrastructure is a
//! separate, bigger problem involving signed updates).

use serde::Serialize;
use std::cmp::Ordering;

/// `<owner>/<repo>` on GitHub (canonical casing). Used to build the API URL
/// for the releases query and the user-facing repo URL.
pub const GITHUB_REPO: &str = "joffrey-b/solanum";

/// How many releases to ask GitHub for, newest first. Plenty to see past a
/// hotfix on an old line, and it keeps a normal answer under the cap below (a
/// release with its assets and notes is about 25 KB of JSON).
const RELEASES_PER_PAGE: u32 = 30;

/// The most this check reads from the network. The answer's size is the
/// server's choice, and none of it is needed beyond a version and a link.
const MAX_RELEASES_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub version: String,
    pub github_repo_url: String,
    pub github_releases_url: String,
}

/// Static info bundled with the binary. Version comes from CARGO_PKG_VERSION
/// which Cargo + tauri-action set from the git tag during release builds.
#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        github_repo_url: format!("https://github.com/{}", GITHUB_REPO),
        github_releases_url: format!("https://github.com/{}/releases", GITHUB_REPO),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateInfo {
    /// Current bundled version (semver, no "v" prefix).
    pub current: String,
    /// Latest release tag on GitHub, with "v" stripped to match `current`.
    /// `None` if the API call failed or no release exists.
    pub latest: Option<String>,
    /// True when the highest published, non-prerelease release on GitHub is a
    /// strictly newer semver than the running build (per-component NUMERIC
    /// compare — see `semver_greater`). Frontend uses this to colour the
    /// banner (green = up-to-date, amber = update available).
    pub has_update: bool,
    /// Direct link to the latest release page. Frontend shows an "Open
    /// release notes" button when has_update is true.
    pub release_url: Option<String>,
}

/// Subset of GitHub's `/releases/latest` JSON we actually care about.
/// Marked non_exhaustive-friendly via #[serde(default)] so a future
/// addition / rename on GitHub's side doesn't break us.
#[derive(Debug, serde::Deserialize)]
struct GhRelease {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// Ask GitHub which release is newest and whether it beats the running build.
///
/// We pull the RELEASES LIST rather than `/releases/latest`: GitHub's "latest"
/// flag is date-based (and manually overridable), so a hotfix published on an
/// old line could point it at a lower version than what's actually shipped.
/// Instead we scan the newest published, non-prerelease releases and pick the
/// highest SEMVER ourselves, then compare that to `current`. Anonymous calls are
/// rate-limited to ~60/hour per IP — fine for a check made once per launch and
/// from the About panel's button. The timeout is short so a hung connection
/// can't freeze the About modal.
#[tauri::command]
pub async fn check_for_updates() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let url = format!(
        "https://api.github.com/repos/{}/releases?per_page={}",
        GITHUB_REPO, RELEASES_PER_PAGE
    );

    // Build a fresh client per call rather than holding state — this is
    // a one-shot probe, not a hot path. User-Agent is required by the
    // GitHub API; an empty/missing UA gets a 403.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .user_agent(concat!("solanum-app/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("[UPDATE] CLIENT: {}", e))?;

    let mut resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("[UPDATE] NETWORK: {}", e))?;

    if !resp.status().is_success() {
        // 404 means the repo path is wrong; anything else is a transient
        // GitHub / rate-limit error. Either way, don't nag — report "no
        // newer release known" so the UI stays quiet rather than scary.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(UpdateInfo { current, latest: None, has_update: false, release_url: None });
        }
        return Err(format!("[UPDATE] HTTP {}", resp.status()));
    }

    // An empty repo returns `[]` (200), not 404 — handled naturally below.
    let body = read_body_capped(&mut resp, MAX_RELEASES_BODY).await?;
    summarize_releases(&body, current)
}

/// Reads a response to its end, refusing one longer than `limit` as soon as
/// it gets there, so the size of what is held never depends on the server.
async fn read_body_capped(resp: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("[UPDATE] NETWORK: {}", e))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err("[UPDATE] TOO_LARGE: the release list is larger than expected".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Picks the highest published, non-prerelease version out of GitHub's answer
/// and compares it to the running build. Drafts are only visible with auth
/// (we're anonymous) but are skipped defensively all the same.
fn summarize_releases(body: &[u8], current: String) -> Result<UpdateInfo, String> {
    let releases: Vec<GhRelease> =
        serde_json::from_slice(body).map_err(|e| format!("[UPDATE] BAD_JSON: {}", e))?;

    let mut best: Option<(String, String)> = None; // (clean_version, html_url)
    for r in releases {
        if r.draft || r.prerelease || r.tag_name.is_empty() {
            continue;
        }
        let clean = r.tag_name.strip_prefix('v').unwrap_or(&r.tag_name).to_string();
        let wins = match &best {
            None => true,
            Some((cur_best, _)) => semver_greater(&clean, cur_best),
        };
        if wins {
            best = Some((clean, r.html_url));
        }
    }

    match best {
        None => Ok(UpdateInfo { current, latest: None, has_update: false, release_url: None }),
        Some((latest_clean, html_url)) => {
            let has_update = semver_greater(&latest_clean, &current);
            Ok(UpdateInfo {
                current,
                latest: Some(latest_clean),
                has_update,
                release_url: if html_url.is_empty() { None } else { Some(html_url) },
            })
        }
    }
}

/// True when `a` is a later version than `b`, in SemVer precedence: the numbers
/// first, then a pre-release sorts below its own release ("0.4.0" > "0.4.0-rc.1").
/// A tag is whatever a release was named, so anything that is not a number
/// counts as 0 instead of failing.
fn semver_greater(a: &str, b: &str) -> bool {
    let (a_core, a_pre) = split_version(a);
    let (b_core, b_pre) = split_version(b);
    for i in 0..a_core.len().max(b_core.len()) {
        let av = a_core.get(i).copied().unwrap_or(0);
        let bv = b_core.get(i).copied().unwrap_or(0);
        if av != bv {
            return av > bv;
        }
    }
    match (a_pre, b_pre) {
        (None, None) | (Some(_), None) => false,
        (None, Some(_)) => true,
        (Some(a), Some(b)) => compare_pre_release(a, b) == Ordering::Greater,
    }
}

/// The dotted numbers and the pre-release part of a version. Build metadata
/// ("+abc") plays no part in precedence.
fn split_version(version: &str) -> (Vec<u64>, Option<&str>) {
    let version = version.split('+').next().unwrap_or(version);
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    (core.split('.').map(|part| part.parse().unwrap_or(0)).collect(), pre)
}

/// SemVer's rule for two pre-releases: field by field, numbers as numbers and
/// below words, words in ASCII order, and the longer list wins a tie.
fn compare_pre_release(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    loop {
        let order = match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => match (x.parse::<u64>(), y.parse::<u64>()) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => x.cmp(y),
            },
        };
        if order != Ordering::Equal {
            return order;
        }
    }
}

/// Open a URL in the user's default browser. URL must be http(s) — we
/// refuse file://, javascript:, and anything else to avoid being a
/// privileged drop-tool for the webview. On Android tauri-plugin-opener
/// dispatches to ACTION_VIEW (the `open` crate has no Android backend); on
/// desktop `child_env::open_detached` starts the browser with the user's
/// environment, not the one Solanum's window runs with (F-014).
#[tauri::command]
pub fn open_external_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let lowered = url.to_ascii_lowercase();
    if !(lowered.starts_with("https://") || lowered.starts_with("http://")) {
        return Err("[OPEN] only http(s) urls are allowed".into());
    }
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url(&url, None::<&str>)
            .map_err(|e| format!("[OPEN] {}", e))
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        crate::child_env::open_detached(url.as_ref()).map_err(|e| format!("[OPEN] {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_is_newer_than_its_own_pre_releases() {
        assert!(semver_greater("0.4.0", "0.4.0-rc.1"));
        assert!(!semver_greater("0.4.0-rc.1", "0.4.0"));
        assert!(semver_greater("0.4.0-rc.1", "0.3.8"));
        assert!(!semver_greater("0.3.8", "0.4.0-rc.1"));
    }

    #[test]
    fn pre_releases_compare_field_by_field() {
        assert!(semver_greater("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(semver_greater("1.0.0-rc.11", "1.0.0-rc.2"), "numeric fields compare as numbers");
        assert!(semver_greater("1.0.0-rc", "1.0.0-beta"));
        assert!(semver_greater("1.0.0-alpha.1", "1.0.0-alpha"), "more fields win when the rest is equal");
        assert!(semver_greater("1.0.0-alpha", "1.0.0-1"), "a word sorts above a number");
    }

    #[test]
    fn plain_versions_keep_comparing_by_number() {
        assert!(semver_greater("0.10.0", "0.9.9"));
        assert!(semver_greater("1.0.0", "0.9.9"));
        assert!(!semver_greater("1.0.0", "1.0"), "a missing part counts as zero");
        assert!(!semver_greater("1.2.3", "1.2.3"));
    }

    #[test]
    fn build_metadata_is_ignored() {
        assert!(!semver_greater("1.0.0+build.2", "1.0.0+build.1"));
        assert!(!semver_greater("1.0.0+build.1", "1.0.0"));
        assert!(semver_greater("1.0.0+build.1", "1.0.0-rc.1"));
    }

    /// A one-connection HTTP server on loopback: answers with `chunk` again and
    /// again in chunked encoding, `repeat` times or until the client hangs up.
    /// Returns its URL.
    async fn serve_chunks(chunk: Vec<u8>, repeat: Option<usize>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = socket.read(&mut buffer).await.unwrap();
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
            if socket.write_all(head).await.is_err() {
                return;
            }
            let mut sent = 0;
            while repeat.is_none_or(|limit| sent < limit) {
                let mut framed = format!("{:x}\r\n", chunk.len()).into_bytes();
                framed.extend_from_slice(&chunk);
                framed.extend_from_slice(b"\r\n");
                if socket.write_all(&framed).await.is_err() {
                    return;
                }
                sent += 1;
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });
        format!("http://{}/", address)
    }

    fn loopback_client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn an_endless_answer_is_refused_just_past_the_cap() {
        let url = serve_chunks(vec![b'x'; 16 * 1024], None).await;
        let mut response = loopback_client().get(&url).send().await.unwrap();
        let error = read_body_capped(&mut response, 64 * 1024).await.unwrap_err();
        assert!(error.starts_with("[UPDATE] TOO_LARGE"), "{}", error);
    }

    #[tokio::test]
    async fn an_answer_exactly_at_the_cap_is_read_whole() {
        let url = serve_chunks(vec![b'x'; 16 * 1024], Some(4)).await;
        let mut response = loopback_client().get(&url).send().await.unwrap();
        let body = read_body_capped(&mut response, 64 * 1024).await.unwrap();
        assert_eq!(body.len(), 64 * 1024);
    }

    #[test]
    fn the_highest_published_release_wins() {
        let body = br#"[
            {"tag_name":"v0.9.0","html_url":"https://example.invalid/old","draft":false,"prerelease":false},
            {"tag_name":"v2.0.0","html_url":"https://example.invalid/draft","draft":true,"prerelease":false},
            {"tag_name":"v3.0.0-rc.1","html_url":"https://example.invalid/rc","draft":false,"prerelease":true},
            {"tag_name":"v1.4.0","html_url":"https://example.invalid/new","draft":false,"prerelease":false},
            {"tag_name":"","html_url":"https://example.invalid/none"}
        ]"#;
        let info = summarize_releases(body, "1.0.0".to_string()).unwrap();
        assert_eq!(info.latest.as_deref(), Some("1.4.0"));
        assert_eq!(info.release_url.as_deref(), Some("https://example.invalid/new"));
        assert!(info.has_update);
    }

    #[test]
    fn a_running_pre_release_is_told_about_its_release() {
        let body = br#"[{"tag_name":"v0.4.0","html_url":"https://example.invalid/r"}]"#;
        assert!(summarize_releases(body, "0.4.0-rc.1".to_string()).unwrap().has_update);
        assert!(!summarize_releases(body, "0.4.0".to_string()).unwrap().has_update);
        assert!(!summarize_releases(body, "0.5.0-rc.1".to_string()).unwrap().has_update);
    }

    #[test]
    fn no_releases_and_bad_json_are_told_apart() {
        let empty = summarize_releases(b"[]", "1.0.0".to_string()).unwrap();
        assert!(empty.latest.is_none() && !empty.has_update && empty.release_url.is_none());
        let error = summarize_releases(b"<html>", "1.0.0".to_string()).unwrap_err();
        assert!(error.starts_with("[UPDATE] BAD_JSON"), "{}", error);
    }

    #[test]
    fn a_normal_page_of_releases_fits_under_the_cap() {
        // What one release of Solanum looks like in GitHub's answer, generously.
        const ONE_RELEASE_JSON: usize = 32 * 1024;
        assert!(RELEASES_PER_PAGE as usize * ONE_RELEASE_JSON <= MAX_RELEASES_BODY);
    }

    #[test]
    fn odd_tags_never_panic() {
        for tag in ["", "-", "+", ".", "nightly", "v1.2.3", "1..2", "1.0.0-", "99999999999999999999999.0.0"] {
            let _ = semver_greater(tag, "1.0.0");
            let _ = semver_greater("1.0.0", tag);
            let _ = semver_greater(tag, tag);
        }
    }
}
