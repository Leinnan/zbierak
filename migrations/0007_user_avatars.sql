-- Profile avatars. Uploaded images are decoded, center-cropped, resized, and
-- re-encoded to PNG before storage, so the table only ever holds normalized
-- image/png bytes. A row's absence means the UI falls back to generated
-- initials derived from the display name.
CREATE TABLE user_avatars (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    bytes BLOB NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
