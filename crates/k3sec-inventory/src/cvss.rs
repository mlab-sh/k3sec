//! CVSS v3.0 / v3.1 base score from its vector, as FIRST specifies it
//! (`first.org/cvss/v3.1/specification-document`, section 7). Most OSV
//! records carry the vector: scoring it here spares a lookup per CVE.

/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8. `None` when it is
/// not a complete v3 vector.
pub fn v3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    if !matches!(parts.next()?, "CVSS:3.0" | "CVSS:3.1") {
        return None;
    }
    let (mut av, mut ac, mut pr, mut ui, mut s, mut c, mut i, mut a) =
        (None, None, None, None, None, None, None, None);
    for m in parts {
        let (k, v) = m.split_once(':')?;
        match k {
            "AV" => av = Some(v),
            "AC" => ac = Some(v),
            "PR" => pr = Some(v),
            "UI" => ui = Some(v),
            "S" => s = Some(v),
            "C" => c = Some(v),
            "I" => i = Some(v),
            "A" => a = Some(v),
            _ => {} // temporal / environmental metrics: not part of the base score
        }
    }
    let changed = match s? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match av? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match ac? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (pr?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match ui? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |x: Option<&str>| match x? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let (c, i, a) = (cia(c)?, cia(i)?, cia(a)?);

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(roundup(raw.min(10.0)))
}

/// CVSS v3.1 Roundup: the smallest one-decimal number ≥ x, computed on
/// integers so 4.000000001 does not become 4.1.
fn roundup(x: f64) -> f64 {
    let n = (x * 100_000.0).round() as i64;
    if n % 10_000 == 0 {
        n as f64 / 100_000.0
    } else {
        ((n / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_match_nvd() {
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0), // Log4Shell
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),  // regreSSHion
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
            ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P", 5.3),
        ];
        for (v, want) in cases {
            assert_eq!(v3_base_score(v), Some(want), "{v}");
        }
    }

    #[test]
    fn rejects_other_versions_and_incomplete_vectors() {
        assert_eq!(
            v3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H"),
            None
        );
        assert_eq!(v3_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), None);
        assert_eq!(
            v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
            None
        );
        assert_eq!(
            v3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
    }
}
