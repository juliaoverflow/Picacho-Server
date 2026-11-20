//! Sequence sets (`1:3,5,7:*`) and flag helpers.

pub const STAR: i64 = i64::MAX;

#[derive(Debug, Clone, PartialEq)]
pub struct SeqSet(pub Vec<(i64, i64)>);

impl SeqSet {
    pub fn parse(s: &str) -> Option<SeqSet> {
        if s.is_empty() || s.len() > 100_000 {
            return None;
        }
        let num = |x: &str| -> Option<i64> {
            if x == "*" {
                Some(STAR)
            } else {
                if x.is_empty() || !x.bytes().all(|c| c.is_ascii_digit()) || x.len() > 10 {
                    return None;
                }
                let n: i64 = x.parse().ok()?;
                if n == 0 || n > u32::MAX as i64 {
                    None
                } else {
                    Some(n)
                }
            }
        };
        let mut out = vec![];
        for item in s.split(',') {
            match item.split_once(':') {
                Some((a, b)) => {
                    let (a, b) = (num(a)?, num(b)?);
                    out.push((a.min(b), a.max(b)));
                }
                None => {
                    let n = num(item)?;
                    out.push((n, n));
                }
            }
        }
        Some(SeqSet(out))
    }

    /// Resolve `*` to `max` (the highest number in use).
    fn resolve(&self, max: i64) -> Vec<(i64, i64)> {
        self.0
            .iter()
            .map(|&(a, b)| {
                let a = if a == STAR { max } else { a };
                let b = if b == STAR { max } else { b };
                (a.min(b), a.max(b))
            })
            .collect()
    }

    /// Message sequence numbers; None when any number is out of range.
    pub fn msns(&self, exists: usize) -> Option<Vec<usize>> {
        let max = exists as i64;
        let mut out = vec![];
        for (a, b) in self.resolve(max) {
            if a < 1 || b > max {
                return None;
            }
            for n in a..=b {
                out.push(n as usize);
            }
        }
        out.sort_unstable();
        out.dedup();
        Some(out)
    }

    /// Indices (0-based) of view entries whose UID is in the set. `*` is the
    /// highest UID present (RFC 3501: "*" in a UID set is the largest UID).
    pub fn uid_indices(&self, uids: &[i64]) -> Vec<usize> {
        let max = uids.last().copied().unwrap_or(0);
        let ranges = self.resolve(max);
        let mut out = vec![];
        for (i, u) in uids.iter().enumerate() {
            if ranges.iter().any(|&(a, b)| *u >= a && *u <= b) {
                out.push(i);
            }
        }
        out
    }

    pub fn contains(&self, n: i64, max: i64) -> bool {
        self.resolve(max).iter().any(|&(a, b)| n >= a && n <= b)
    }
}

/// Compress sorted numbers into an IMAP set (`1:3,7`).
pub fn compress(nums: &[i64]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < nums.len() {
        let start = nums[i];
        let mut end = start;
        while i + 1 < nums.len() && nums[i + 1] == end + 1 {
            i += 1;
            end = nums[i];
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}:{end}"));
        }
        i += 1;
    }
    out
}

pub const SYSTEM_FLAGS: [&str; 5] = ["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"];

/// Canonical form of a flag: system flags in standard case; keywords kept.
/// None for invalid flags.
pub fn canonical_flag(f: &str) -> Option<String> {
    if let Some(rest) = f.strip_prefix('\\') {
        let _ = rest;
        return SYSTEM_FLAGS.iter().find(|s| s.eq_ignore_ascii_case(f)).map(|s| s.to_string());
    }
    if f.is_empty() || f.len() > 128 || !f.bytes().all(|c| c > b' ' && c < 0x7f && !b"(){%*\"\\]".contains(&c)) {
        return None;
    }
    Some(f.to_string())
}

pub fn split_flags(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

pub fn has_flag(flags: &str, f: &str) -> bool {
    flags.split_whitespace().any(|x| x.eq_ignore_ascii_case(f))
}

pub fn join_flags(flags: &[String]) -> String {
    flags.join(" ")
}

/// Normalize a flags string for comparison.
pub fn norm_flags(s: &str) -> Vec<String> {
    let mut v: Vec<String> = s.split_whitespace().map(|x| x.to_ascii_lowercase()).collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sets() {
        let s = SeqSet::parse("1:3,5,7:*").unwrap();
        assert_eq!(s.msns(8).unwrap(), vec![1, 2, 3, 5, 7, 8]);
        assert!(SeqSet::parse("1:3").unwrap().msns(2).is_none());
        assert!(SeqSet::parse("0").is_none());
        let u = SeqSet::parse("100:*").unwrap();
        assert_eq!(u.uid_indices(&[1, 5, 50]), vec![2]);
        assert_eq!(compress(&[1, 2, 3, 5, 7, 8]), "1:3,5,7:8");
    }
}
