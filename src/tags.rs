//! Normalization and validation for flat string issue tags.

use std::collections::BTreeMap;
use std::collections::HashSet;

/// Maximum number of tags stored on a single issue.
pub const MAX_TAGS: usize = 50;

/// Maximum length of a single tag.
const MAX_TAG_LEN: usize = 64;

/// Validates one raw tag without allocating: trims whitespace and enforces
/// the tag charset, returning the trimmed form.
///
/// Tags may not contain whitespace or commas because the operator UI collects
/// them as comma-separated lists and query strings.
pub fn validate_tag(raw: &str) -> Result<&str, String> {
    let tag = raw.trim();
    if tag.is_empty() {
        return Err("must not be empty".into());
    }
    if tag.chars().count() > MAX_TAG_LEN {
        return Err(format!("must contain at most {MAX_TAG_LEN} characters"));
    }
    if tag
        .chars()
        .any(|character| character.is_whitespace() || character == ',')
    {
        return Err("must not contain whitespace or commas".into());
    }
    Ok(tag)
}

/// Normalizes a list of raw tags, skipping empty entries and dropping
/// duplicates while preserving order. Only accepted unique tags are
/// allocated.
pub fn normalize_tags<'a, I>(raw: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut tags = Vec::new();
    let mut seen = HashSet::new();
    for value in raw {
        if value.trim().is_empty() {
            continue;
        }
        let tag = validate_tag(value).map_err(|error| format!("tag {error}"))?;
        if seen.insert(tag) {
            tags.push(tag.to_owned());
        }
    }
    if tags.len() > MAX_TAGS {
        return Err(format!("must contain at most {MAX_TAGS} tags"));
    }
    Ok(tags)
}

/// Splits a comma-separated raw input (operator UI) into normalized tags.
pub fn normalize_comma_separated(input: &str) -> Result<Vec<String>, String> {
    normalize_tags(input.split(','))
}

/// Derives issue tag labels from an event's key/value tag map.
///
/// Labels use `key:value` form, or `key` alone when the value is empty.
/// Labels that violate the issue-tag rules are skipped so a malformed event
/// tag cannot reject an otherwise valid event at ingest time.
pub fn labels_from_event_tags(event_tags: &BTreeMap<String, String>) -> Vec<String> {
    event_tags
        .iter()
        .filter_map(|(key, value)| {
            let label = if value.is_empty() {
                key.as_str()
            } else {
                return validate_tag(&format!("{key}:{value}"))
                    .ok()
                    .map(str::to_owned);
            };
            validate_tag(label).ok().map(str::to_owned)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::*;

    #[test]
    fn validate_tag_trims_and_rejects() {
        assert_eq!(validate_tag(" env:prod "), Ok("env:prod"));
        assert!(validate_tag("").is_err());
        assert!(validate_tag("   ").is_err());
        assert!(validate_tag("a b").is_err());
        assert!(validate_tag("a,b").is_err());
        assert!(validate_tag("x".repeat(65).as_str()).is_err());
        assert_eq!(validate_tag("x").unwrap().len(), 1);
    }

    #[test]
    fn normalize_tags_dedupes_and_caps() {
        let tags = normalize_tags(["a", " a ", "b", ""]).unwrap();
        assert_eq!(tags, vec!["a".to_owned(), "b".to_owned()]);
        let many: Vec<String> = (0..=MAX_TAGS).map(|i| format!("t{i}")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(normalize_tags(refs).is_err());
    }
    #[test]
    fn comma_separated_input_splits_and_trims() {
        let tags = normalize_comma_separated("env:prod, region:eu ,, ").unwrap();
        assert_eq!(tags, vec!["env:prod".to_owned(), "region:eu".to_owned()]);
        assert!(normalize_comma_separated("bad tag").is_err());
    }

    #[test]
    fn event_tags_become_key_value_labels() {
        let mut map = BTreeMap::new();
        map.insert("env".to_owned(), "prod".to_owned());
        map.insert("shard".to_owned(), String::new());
        map.insert("bad tag".to_owned(), "value".to_owned());
        let labels = labels_from_event_tags(&map);
        assert_eq!(labels, vec!["env:prod".to_owned(), "shard".to_owned()]);
    }

    #[test]
    fn oversize_event_tags_are_skipped() {
        let mut map = BTreeMap::new();
        map.insert("k".to_owned(), "v".repeat(100));
        assert!(labels_from_event_tags(&map).is_empty());
    }
}
