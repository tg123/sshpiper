use std::collections::HashSet;

use anyhow::{bail, Result};

pub(crate) struct TypePolicy {
    allowed: Option<HashSet<String>>,
    denied: HashSet<String>,
}

impl TypePolicy {
    pub(crate) fn new(
        kind: &str,
        allowed: &[String],
        denied: &[String],
        always_denied: &[&str],
    ) -> Result<Self> {
        if !allowed.is_empty() && !denied.is_empty() {
            bail!("--allowed-{kind} and --denied-{kind} are mutually exclusive, set only one");
        }
        let parse = |values: &[String]| {
            values
                .iter()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<HashSet<_>>()
        };
        // An explicitly empty allowlist denies everything, unlike an unset list.
        let allowed = (!allowed.is_empty()).then(|| parse(allowed));
        let mut denied = parse(denied);
        denied.extend(always_denied.iter().map(|value| (*value).to_owned()));
        Ok(Self { allowed, denied })
    }

    pub(crate) fn blocked(&self, kind: &str) -> bool {
        self.denied.contains(kind)
            || self
                .allowed
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_without_losing_allowlist_presence_or_case() {
        for (allowed, denied, sugar, expected) in [
            (vec![], vec![], vec![], [false, false, false]),
            (vec![" "], vec![], vec![], [true, true, true]),
            (vec![], vec![" "], vec![], [false, false, false]),
            (
                vec![" session ", "session"],
                vec![],
                vec![],
                [false, true, true],
            ),
            (vec![], vec![" x11 "], vec![], [false, true, false]),
            (
                vec!["session", "x11"],
                vec![],
                vec!["x11"],
                [false, true, true],
            ),
            (vec![], vec!["x11"], vec!["session"], [true, true, false]),
            (vec![], vec![], vec!["session"], [true, false, false]),
        ] {
            let policy = TypePolicy::new(
                "types",
                &allowed.into_iter().map(str::to_owned).collect::<Vec<_>>(),
                &denied.into_iter().map(str::to_owned).collect::<Vec<_>>(),
                &sugar,
            )
            .unwrap();
            for (kind, blocked) in ["session", "x11", "Session"].into_iter().zip(expected) {
                assert_eq!(policy.blocked(kind), blocked, "{kind}");
            }
        }
        assert!(TypePolicy::new("types", &[" ".into()], &["".into()], &[]).is_err());
    }
}
