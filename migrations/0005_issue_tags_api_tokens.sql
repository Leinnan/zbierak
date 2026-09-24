-- Issue tags: flat string labels. Derived from event tags on ingest and
-- maintained manually through the UI or the management API.
CREATE TABLE issue_tags (
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (issue_id, tag)
);
CREATE INDEX issue_tags_tag_idx ON issue_tags(tag);

-- Personal API tokens authenticate the versioned management API
-- (issue listing, filtering, and tag editing) as the owning user.
CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX api_tokens_user_idx ON api_tokens(user_id, created_at DESC);

-- Tag edits are recorded in the issue timeline, so the kind CHECK needs a
-- new allowed value. SQLite cannot alter a CHECK, so rebuild the table.
CREATE TABLE issue_activity_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN ('status', 'comment', 'regression', 'tags')),
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO issue_activity_new (id, issue_id, user_id, kind, details_json, created_at)
SELECT id, issue_id, user_id, kind, details_json, created_at FROM issue_activity;

DROP TABLE issue_activity;
ALTER TABLE issue_activity_new RENAME TO issue_activity;
CREATE INDEX issue_activity_issue_created_idx
    ON issue_activity(issue_id, created_at DESC, id DESC);
