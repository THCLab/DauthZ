//! Where to send the user after sign-in.
//!
//! nginx's `return 302 /dauthz/login?return=$request_uri` does not encode
//! `$request_uri`, so `?return=/guides/x?tab=1` arrives with a second `?`
//! inside. The login page therefore reads `return` as the raw tail after
//! the first `return=`. The JS then sends it back to `/connect/init`
//! properly encoded, where normal query parsing applies.

/// Raw tail after `return=` in a query string (no decoding).
pub fn raw_return(query: Option<&str>) -> Option<String> {
    let q = query?;
    let idx = q.find("return=")?;
    let preceded_ok = idx == 0 || q.as_bytes()[idx - 1] == b'&';
    if !preceded_ok {
        return None;
    }
    Some(q[idx + "return=".len()..].to_string())
}

/// Accept only same-origin absolute paths, never the gate's own routes.
pub fn sanitize(candidate: Option<&str>, prefix: &str) -> String {
    let Some(c) = candidate.map(str::trim).filter(|c| !c.is_empty()) else {
        return "/".into();
    };
    let ok = c.starts_with('/')
        && !c.starts_with("//")
        && !c.starts_with("/\\")
        && !c.contains('\\')
        && !c.chars().any(|ch| ch.is_control())
        && !(c == prefix
            || c.starts_with(&format!("{prefix}/"))
            || c.starts_with(&format!("{prefix}?")));
    if ok {
        c.to_string()
    } else {
        "/".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_tail_keeps_nested_query_strings() {
        assert_eq!(
            raw_return(Some("return=/guides/x?tab=1&y=2")).as_deref(),
            Some("/guides/x?tab=1&y=2")
        );
        assert_eq!(raw_return(Some("a=1&return=/x")).as_deref(), Some("/x"));
        assert_eq!(raw_return(Some("noreturn=/x")), None);
        assert_eq!(raw_return(None), None);
    }

    #[test]
    fn sanitize_refuses_offsite_and_gate_paths() {
        assert_eq!(sanitize(Some("/guides/x"), "/dauthz"), "/guides/x");
        assert_eq!(sanitize(Some("//evil.example"), "/dauthz"), "/");
        assert_eq!(sanitize(Some("https://evil.example"), "/dauthz"), "/");
        assert_eq!(sanitize(Some("/dauthz/login"), "/dauthz"), "/");
        assert_eq!(sanitize(Some("/dauthz"), "/dauthz"), "/");
        assert_eq!(sanitize(Some("/dauthzish"), "/dauthz"), "/dauthzish");
        assert_eq!(sanitize(Some("/x\r\nSet-Cookie: a"), "/dauthz"), "/");
        assert_eq!(sanitize(None, "/dauthz"), "/");
    }
}
