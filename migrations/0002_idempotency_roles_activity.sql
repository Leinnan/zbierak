CREATE TABLE project_memberships_new (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (project_id, user_id)
);

INSERT INTO project_memberships_new (project_id, user_id, role, created_at)
SELECT project_id, user_id,
       CASE role WHEN 'member' THEN 'developer' ELSE role END,
       created_at
FROM project_memberships;

DROP TABLE project_memberships;
ALTER TABLE project_memberships_new RENAME TO project_memberships;

ALTER TABLE projects ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE projects ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'archived'));

ALTER TABLE raw_events ADD COLUMN producer_event_id TEXT;
UPDATE raw_events SET producer_event_id = id WHERE producer_event_id IS NULL;
CREATE UNIQUE INDEX raw_events_project_producer_id_idx
    ON raw_events(project_id, producer_event_id);

CREATE TABLE issue_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN ('status', 'comment', 'regression')),
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX issue_activity_issue_created_idx
    ON issue_activity(issue_id, created_at DESC, id DESC);
