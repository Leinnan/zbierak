-- Comment editing and moderation: edits are attributed (updated_at, updated_by)
-- and removals are soft deletes (deleted_at) so the timeline can show
-- tombstones instead of silently losing discussion history.
ALTER TABLE issue_comments ADD COLUMN updated_at INTEGER;
ALTER TABLE issue_comments ADD COLUMN updated_by INTEGER REFERENCES users(id);
ALTER TABLE issue_comments ADD COLUMN deleted_at INTEGER;

-- Comment listing is always scoped to one issue and ordered chronologically;
-- the index makes that the only access pattern.
CREATE INDEX issue_comments_issue_created_idx
    ON issue_comments(issue_id, created_at, id);

-- Comment edits and removals are recorded in the issue timeline, so the kind
-- CHECK needs new allowed values. SQLite cannot alter a CHECK, so rebuild.
CREATE TABLE issue_activity_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN ('status', 'comment', 'regression', 'tags',
                                       'comment_edited', 'comment_deleted')),
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO issue_activity_new (id, issue_id, user_id, kind, details_json, created_at)
SELECT id, issue_id, user_id, kind, details_json, created_at FROM issue_activity;

DROP TABLE issue_activity;
ALTER TABLE issue_activity_new RENAME TO issue_activity;
CREATE INDEX issue_activity_issue_created_idx
    ON issue_activity(issue_id, created_at DESC, id DESC);
