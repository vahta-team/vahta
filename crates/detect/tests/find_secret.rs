//! `find_secret` end to end: what the hook asks, and what it must not flag.
//! Every credential-shaped value is built from pieces at run time.

use vahta_detect::{Confidence, Evasion, Mode, find_secret};

fn aws() -> String {
    [
        "wJ7r", "Xu9t", "nFEM", "I2Kd", "Mq7Q", "bPxR", "fiCY", "5Zk3", "Ha8L", "tW0s",
    ]
    .concat()
}

fn anthropic() -> String {
    ["sk-", "ant-", "api03-", "Zk9pL2xQ7mN4vB8wR3tY6uHs1DfG"].concat()
}

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                out.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn pct(text: &str) -> String {
    text.bytes().map(|b| format!("%{b:02X}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn plain_forms_name_a_category_and_a_rule() {
    let f = find_secret(&format!("AWS_SECRET_ACCESS_KEY={} aws s3 ls", aws())).unwrap();
    assert_eq!(f.rule, "vahta.assignment");
    assert_eq!(f.category, "a secret assigned to AWS_SECRET_ACCESS_KEY");
    assert_eq!(f.confidence, Confidence::Likely);
    assert_eq!(f.evasion, None);
    assert_eq!(f.mode, Mode::Block);

    let f = find_secret(&format!("curl -H 'x-api-key: {}'", anthropic())).unwrap();
    assert_eq!(f.rule, "vahta.prefix.anthropic");
    assert_eq!(f.category, "an Anthropic-style API key");
}

#[test]
fn the_agent_category_never_holds_the_rule_id_or_the_value() {
    for text in [
        format!("AWS_SECRET_ACCESS_KEY={}", aws()),
        format!("k={}", anthropic()),
        format!("postgres://app:{}@db/x", aws()),
    ] {
        let f = find_secret(&text).unwrap();
        assert!(!f.category.contains("vahta."), "{}", f.category);
        assert!(!f.category.contains(&aws()), "{}", f.category);
        assert!(!f.description.contains(&aws()));
    }
}

#[test]
fn a_data_rule_hits_and_names_its_source_rule() {
    let token = ["gh", "p_", "scCpjrf9TntYRTnAhKVDbzxopsCdmfJ03sQz"].concat();
    let f = find_secret(&format!("echo {token}")).unwrap();
    // The prefix matcher knows this one first.
    assert_eq!(f.rule, "vahta.prefix.github-pat");
    let hook = [
        "https://hooks.",
        "slack.com/services/",
        "T04KQ7ZXNM/B06RJH2PVD/q8WmT3vZkN5xLr2CjY9pHs4D",
    ]
    .concat();
    let f = find_secret(&format!("curl -X POST {hook}")).unwrap();
    assert_eq!(f.rule, "gitleaks.slack-webhook-url");
    assert_eq!(f.category, "a webhook URL with an embedded secret");
}

#[test]
fn hidden_values_block_and_say_how() {
    let assign = format!("AWS_SECRET_ACCESS_KEY={}", aws());
    let cases: Vec<(String, Evasion)> = vec![
        (
            format!("echo {} | base64 -d | sh", b64(assign.as_bytes())),
            Evasion::Base64,
        ),
        (
            format!("echo {} | base64 -d", b64(anthropic().as_bytes())),
            Evasion::Base64,
        ),
        (
            format!("echo {} | xxd -r -p | sh", hex(assign.as_bytes())),
            Evasion::Hex,
        ),
        (
            format!("export K='{}''{}'", &anthropic()[..9], &anthropic()[9..]),
            Evasion::Concat,
        ),
        (
            format!(
                "k = \"{}\" + \"{}\"",
                &anthropic()[..12],
                &anthropic()[12..]
            ),
            Evasion::Concat,
        ),
        (
            format!(
                "python3 -c \"k = '{}' + '{}'\"",
                &anthropic()[..12],
                &anthropic()[12..]
            ),
            Evasion::Concat,
        ),
        (
            format!("K={}'{}'", &anthropic()[..9], &anthropic()[9..]),
            Evasion::Concat,
        ),
        (
            format!(
                "AWS_SECRET_ACCESS_KEY={}",
                aws()
                    .as_bytes()
                    .chunks(4)
                    .map(|c| format!("'{}'", String::from_utf8_lossy(c)))
                    .collect::<String>()
            ),
            Evasion::Concat,
        ),
    ];
    for (n, (text, how)) in cases.into_iter().enumerate() {
        let f = find_secret(&text).unwrap_or_else(|| panic!("case {n} missed: {how:?}"));
        assert_eq!(f.evasion, Some(how), "{text}");
        assert_eq!(f.mode, Mode::Block);
        assert_eq!(f.confidence, Confidence::Likely);
    }
}

#[test]
fn ordinary_encoded_and_quoted_text_is_left_alone() {
    for text in [
        "echo SGVsbG8gd29ybGQsIHRoaXMgaXMgYSBwbGFpbiBncmVldGluZw== | base64 -d",
        "git show da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "git commit -m 'one' -m 'two' && echo 'a''b'",
        "sha512-9nI5j1ZLq0X3nqTfT0qN2uYk7bGdQp0m1c2rXwHhVtJ4yB6vA8sKzEoDlPfC3gUiM5aN7wRx",
        "ls -la /usr/local/lib/python3.12/site-packages/some_very_long_package_name_here",
        "const greeting = 'hello' + ' ' + 'world';",
        // Quotes that pair wrongly must not make a "value cut in two".
        "fn modifier(&self, token: Spanned<&'input str>) -> Result<Modifier<'input>, Error> {",
        "'params': {'videopassword': 'seniorinfants2'},",
        "let password = b\"hunter42\"; // a bad password, don't use it",
    ] {
        assert_eq!(find_secret(text), None, "{text}");
    }
}

#[test]
fn nothing_found_is_none_and_a_plain_command_is_quick() {
    assert!(find_secret("cargo build --release && ls -la").is_none());
    assert!(find_secret("").is_none());
}

#[test]
fn padding_past_one_window_does_not_hide_a_data_rule_hit() {
    let hook = [
        "https://hooks.",
        "slack.com/services/",
        "T04KQ7ZXNM/B06RJH2PVD/q8WmT3vZkN5xLr2CjY9pHs4D",
    ]
    .concat();
    // After a pad of two windows, and across a window seam.
    for pad in [
        1_300_000,
        2_500_000,
        vahta_rules::MAX_SCAN_BYTES - 4096 - 10,
    ] {
        let big = format!("{}\ncurl -X POST {hook}\n", "x ".repeat(pad / 2));
        let d = vahta_detect::detect(&big);
        assert_eq!(d.truncated, None, "{pad}");
        assert_eq!(
            d.finding.unwrap().rule,
            "gitleaks.slack-webhook-url",
            "{pad}"
        );
    }
}

#[test]
fn a_text_past_the_total_cap_is_reported_truncated() {
    let big = "x ".repeat(vahta_rules::MAX_TOTAL_BYTES / 2 + 10);
    let d = vahta_detect::detect(&big);
    assert_eq!(d.truncated, Some(vahta_detect::Truncated::Bytes));
    // The built-in matchers have no size limit.
    let tail = format!("{big}\nAWS_SECRET_ACCESS_KEY={}\n", aws());
    assert_eq!(
        vahta_detect::detect(&tail).finding.unwrap().rule,
        "vahta.assignment"
    );
}

#[test]
fn many_vendor_words_hit_the_rule_cap_but_not_a_vendor_prefix() {
    let words = "adobe airtable algolia asana atlassian beamer bitbucket bittrex cloudflare codecov cohere contentful datadog discord dropbox facebook finicity flickr freshbooks gitter gocardless hubspot intercom lob mailchimp mailgun mapbox messagebird newrelic okta plaid pulumi sendbird sentry shopify squarespace stripe twitch typeform yandex zendesk";
    let d = vahta_detect::detect(words);
    assert_eq!(d.truncated, Some(vahta_detect::Truncated::Rules));
    assert!(d.finding.is_none());
}

#[test]
fn percent_encoded_values_block_and_say_so() {
    let bearer = ["Author", "ization: Bear", "er "].concat();
    for text in [
        format!(
            "curl -H \"{bearer}{}\" https://api.example.com",
            pct(&aws())
        ),
        format!(
            "curl -H '{bearer}{}' https://api.example.com",
            pct(&anthropic())
        ),
        format!(
            "echo {} | python3 -c 'import sys,urllib.parse as u'",
            pct(&anthropic())
        ),
        format!(
            "curl https://api.example.com/?x={}",
            pct(&format!("AWS_SECRET_ACCESS_KEY={}", aws()))
        ),
    ] {
        let f = find_secret(&text).unwrap_or_else(|| panic!("missed: {text}"));
        assert_eq!(f.evasion, Some(Evasion::Percent), "{text}");
        assert_eq!(f.mode, Mode::Block);
        assert_eq!(f.confidence, Confidence::Likely);
    }
}

#[test]
fn ansi_c_quoted_pieces_are_one_value() {
    let a = anthropic();
    let text = format!("export K=$'{}'$'{}'", &a[..9], &a[9..]);
    let f = find_secret(&text).expect("missed");
    assert_eq!(f.evasion, Some(Evasion::Concat));
}

#[test]
fn ordinary_percent_encoding_is_left_alone() {
    let fake = pct("fake-plain-value-1");
    let name = ["API_", "KEY"].concat();
    for text in [
        "curl 'https://example.com/my%20docs/annual%20report%20final.pdf?q=hello%20world'".to_string(),
        "curl 'https://example.com/auth?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback%3Fnext%3D%2Fhome'".to_string(),
        "curl --data 'payload=%7B%22name%22%3A%22bob%22%2C%22items%22%3A%5B1%2C2%2C3%5D%7D' https://example.com".to_string(),
        format!("export {name}={fake} && ./run.sh"),
        format!("echo {} | head", pct("hello world, this is plain text")),
    ] {
        assert!(find_secret(&text).is_none(), "{text}");
    }
}
