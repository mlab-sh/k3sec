mod samples;

use k3sec_api::*;

#[test]
fn v1_bytes_are_frozen() {
    for (name, bytes) in samples::all() {
        let path = format!("{}/tests/golden/{name}.hex", env!("CARGO_MANIFEST_DIR"));
        let golden = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {path}"));
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, golden.trim(), "{name}: the v1 wire format changed");
    }
}

#[test]
fn round_trips() {
    let b = samples::batch();
    assert_eq!(from_cbor::<Batch>(&to_cbor(&b).unwrap()).unwrap(), b);
    let s = samples::status();
    assert_eq!(from_cbor::<Status>(&to_cbor(&s).unwrap()).unwrap(), s);
    let inv = samples::inventory();
    assert_eq!(Inventory::decode(&inv.encode().unwrap()).unwrap(), inv);
}

#[test]
fn unknown_fields_and_versions_are_refused() {
    // A Config with an extra key.
    let mut v: ciborium::Value =
        ciborium::from_reader(to_cbor(&Config::default()).unwrap().as_slice()).unwrap();
    if let ciborium::Value::Map(m) = &mut v {
        m.push(("surprise".into(), true.into()));
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(&v, &mut bytes).unwrap();
    assert!(matches!(
        from_cbor::<Config>(&bytes),
        Err(ApiError::Decode(_))
    ));

    let mut next = samples::inventory();
    next.api_version = API_VERSION + 1;
    assert_eq!(
        Inventory::decode(&next.encode().unwrap()),
        Err(ApiError::UnsupportedVersion(API_VERSION + 1))
    );
    let mut other = samples::inventory();
    other.format = "engram-index".into();
    assert!(matches!(
        Inventory::decode(&other.encode().unwrap()),
        Err(ApiError::Decode(_))
    ));
}

#[test]
fn settings_default_and_partial_policy_tables() {
    // A policy table naming only some keys gets the defaults for the rest.
    use ciborium::Value;
    let table = Value::Map(vec![
        ("allow_remote_rules".into(), true.into()),
        ("namespaces".into(), Value::Array(vec!["prod".into()])),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&table, &mut bytes).unwrap();
    let s: Settings = from_cbor(&bytes).unwrap();
    assert!(s.allow_remote_rules);
    assert_eq!(s.namespaces, ["prod"]);
    assert_eq!(s.allow(), Settings::default().allow());
    assert_eq!(s.backlog_events, 50_000);
}

#[test]
fn rulesets_are_named_by_their_last_component() {
    let s = Settings {
        rulesets: vec![
            "/usr/share/k3sec/rules/".into(),
            "/etc/k3sec/extra.yar".into(),
        ],
        ..Settings::default()
    };
    let names: Vec<String> = s.rulesets().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["rules", "extra"]);
}

#[test]
fn severities_and_sources_keep_their_v1_names() {
    let names: Vec<String> = [
        Severity::Info,
        Severity::Normal,
        Severity::Warning,
        Severity::Error,
        Severity::Critical,
    ]
    .iter()
    .map(|s| {
        serde_json::to_value(s)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
    .collect();
    assert_eq!(names, ["info", "normal", "warning", "error", "critical"]);
    assert_eq!(serde_json::to_value(Source::K8sEvent).unwrap(), "k8s-event");
    assert!(Severity::Warning < Severity::Critical);
}

#[test]
fn a_full_batch_of_typical_events_fits_the_envelope() {
    // Producers also cut on bytes (messages vary); this sizes MAX_BATCH_EVENTS.
    let exec = SecEvent {
        source: Source::Ebpf,
        kind: "exec".into(),
        severity: Severity::Info,
        message: "exec /usr/bin/curl (sh)".into(),
        metadata: [
            ("comm", "sh"),
            ("container", "app"),
            ("container_id", "8ebc3b632630"),
            ("pid", "4242"),
            ("pod", "web-0"),
            ("uid", "0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        payload: serde_json::json!({"pid": 4242, "uid": 0, "comm": "sh", "path": "/usr/bin/curl",
            "container_id": "8ebc3b63263078ea0d58f92706a6541e70e833454902992aa4de32fe91236752"}),
        ..samples::yara_event()
    };
    let full = Batch {
        events: vec![exec; MAX_BATCH_EVENTS],
        ..samples::batch()
    };
    let len = to_cbor(&full).unwrap().len();
    assert!(len < MAX_BATCH_BYTES, "{len} bytes");
}
