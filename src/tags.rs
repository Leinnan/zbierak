//! Normalization and validation for flat string issue tags.

use std::collections::BTreeMap;

/// Maximum number of tags stored on a single issue.
pub const MAX_TAGS: usize = 50;

/// Maximum length of a single tag.
const MAX_TAG_LEN: usize = 64;

/// Normalizes one raw tag: trims whitespace and enforces the tag charset.
///
/// Tags may not contain whitespace or commas because the operator UI collects
/// them as comma-separated lists and query strings.
pub fn normalize_tag(raw: &str) -> Result<String, String> {
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
    Ok(tag.to_owned())
}

/// Normalizes a list of raw tags, skipping empty entries and dropping
/// duplicates while preserving order.
pub fn normalize_tags<'a, I>(raw: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut tags = Vec::new();
    for value in raw {
        if value.trim().is_empty() {
            continue;
        }
        let tag = normalize_tag(value).map_err(|error| format!("tag {error}"))?;
        if !tags.contains(&tag) {
            tags.push(tag);
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
        .map(|(key, value)| {
            if value.is_empty() {
                key.clone()
            } else {
                format!("{key}:{value}")
            }
        })
        .filter_map(|label| normalize_tag(&label).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_tag_trims_and_validates() {
        assert_eq!(normalize_tag(" env:prod "), Ok("env:prod".into()));
        assert!(normalize_tag("").is_err());
        assert!(normalize_tag("   ").is_err());
        assert!(normalize_tag("a b").is_err());
        assert!(normalize_tag("a,b").is_err());
        assert!(normalize_tag(&"x".repeat(65)).is_err());
        assert_eq!(normalize_tag("x").unwrap().len(), 1);
    }

    #[test]
    fn normalize_tags_dedupes_and_caps() {
        let tags = normalize_tags(["a", " a ", "b", ""]).unwrap();
        assert_eq!(tags, vec!["a".to_owned(), "b".to_owned()]);
        let many: Vec<String> = (0..MAX_TAGS + 1).map(|i| format!("t{i}")).collect();
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
