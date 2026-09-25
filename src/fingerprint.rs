use serde_json::Value;

pub fn event_fingerprint(event: &Value) -> String {
    if let Some(parts) = event.get("fingerprint").and_then(Value::as_array)
        && !parts.is_empty()
    {
        let explicit = parts
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        return blake3::hash(format!("explicit\n{explicit}").as_bytes())
            .to_hex()
            .to_string();
    }
    let mut parts = Vec::new();
    collect(event, &mut parts);
    if parts.is_empty() {
        parts.push(canonical(event));
    }
    blake3::hash(parts.join("\n").as_bytes())
        .to_hex()
        .to_string()
}

fn collect(value: &Value, out: &mut Vec<String>) {
    if let Some(object) = value.as_object() {
        for key in ["exception_type", "error_type", "type", "message"] {
            if let Some(text) = object.get(key).and_then(Value::as_str) {
                out.push(format!("{key}:{text}"));
            }
        }
        for key in [
            "frames",
            "stack_frames",
            "stacktrace",
            "exceptions",
            "exception",
            "error",
        ] {
            if let Some(nested) = object.get(key) {
                collect(nested, out);
            }
        }
        if let (Some(file), Some(function)) = (
            object
                .get("filename")
                .or_else(|| object.get("file"))
                .and_then(Value::as_str),
            object
                .get("function")
                .or_else(|| object.get("function_name"))
                .and_then(Value::as_str),
        ) {
            out.push(format!("frame:{file}:{function}"));
        }
    } else if let Some(array) = value.as_array() {
        for nested in array {
            collect(nested, out);
        }
    }
}

fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            entries
                .into_iter()
                .map(|(key, value)| format!("{key}:{}", canonical(value)))
                .collect::<Vec<_>>()
                .join("|")
        }
        Value::Array(values) => values.iter().map(canonical).collect::<Vec<_>>().join(","),
        _ => value.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::event_fingerprint;
    use serde_json::json;

    #[test]
    fn fingerprint_ignores_unrelated_metadata() {
        let a = json!({"message":"boom", "frames":[{"file":"main.rs","function":"run","line":1}], "timestamp":1});
        let b = json!({"message":"boom", "frames":[{"file":"main.rs","function":"run","line":99}], "timestamp":2});
        assert_eq!(event_fingerprint(&a), event_fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_for_stack() {
        assert_ne!(
            event_fingerprint(&json!({"message":"boom", "frames":[{"file":"a","function":"run"}]})),
            event_fingerprint(&json!({"message":"boom", "frames":[{"file":"b","function":"run"}]})),
        );
    }

    #[test]
    fn explicit_fingerprint_controls_grouping() {
        let a = json!({"message":"first", "fingerprint":["service", "timeout"]});
        let b = json!({"message":"second", "fingerprint":["service", "timeout"]});
        assert_eq!(event_fingerprint(&a), event_fingerprint(&b));
    }
}
