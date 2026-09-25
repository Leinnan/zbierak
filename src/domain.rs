//! Domain enumerations shared by authorization and issue handling.
//!
//! Both enums parse from their wire/database spelling at the boundary and
//! reject unknown values, so authorization and status transitions never
//! depend on free-form strings ranking as zero.

use std::fmt;

/// Project membership roles, ordered by capability: a role compares greater
/// than every role it subsumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectRole {
    /// Read-only access.
    Viewer,
    /// Can comment and change issue state.
    Developer,
    /// Can manage keys, members, and webhooks.
    Admin,
    /// Full control, including promoting members to admin.
    Owner,
}

impl ProjectRole {
    /// Every role, weakest first.
    pub const ALL: [ProjectRole; 4] = [
        ProjectRole::Viewer,
        ProjectRole::Developer,
        ProjectRole::Admin,
        ProjectRole::Owner,
    ];

    /// The database and form spelling of the role.
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectRole::Viewer => "viewer",
            ProjectRole::Developer => "developer",
            ProjectRole::Admin => "admin",
            ProjectRole::Owner => "owner",
        }
    }

    /// Parses a role from a form or database value. Unknown spellings return
    /// `None` so callers can fail closed instead of weakening the check.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == raw)
    }
}

impl fmt::Display for ProjectRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Lifecycle states of an issue, matching the database CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueStatus {
    /// The issue is open and not yet dealt with.
    Unresolved,
    /// The issue has been fixed.
    Resolved,
    /// The issue is acknowledged but will not be fixed.
    Ignored,
}

impl IssueStatus {
    /// The database and query spelling of the status.
    pub fn as_str(self) -> &'static str {
        match self {
            IssueStatus::Unresolved => "unresolved",
            IssueStatus::Resolved => "resolved",
            IssueStatus::Ignored => "ignored",
        }
    }

    /// Parses a status from a form or query value.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "unresolved" => Some(IssueStatus::Unresolved),
            "resolved" => Some(IssueStatus::Resolved),
            "ignored" => Some(IssueStatus::Ignored),
            _ => None,
        }
    }
}

impl fmt::Display for IssueStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::{IssueStatus, ProjectRole};

    #[test]
    fn project_roles_are_ordered_by_capability() {
        assert!(ProjectRole::Owner > ProjectRole::Admin);
        assert!(ProjectRole::Admin > ProjectRole::Developer);
        assert!(ProjectRole::Developer > ProjectRole::Viewer);
    }

    #[test]
    fn project_roles_round_trip_through_their_spelling() {
        for role in ProjectRole::ALL {
            assert_eq!(ProjectRole::parse(role.as_str()), Some(role));
        }
        assert_eq!(ProjectRole::parse("owner "), None);
        assert_eq!(ProjectRole::parse("Owner"), None);
        assert_eq!(ProjectRole::parse("unknown"), None);
    }

    #[test]
    fn issue_statuses_round_trip_through_their_spelling() {
        for status in [
            IssueStatus::Unresolved,
            IssueStatus::Resolved,
            IssueStatus::Ignored,
        ] {
            assert_eq!(IssueStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(IssueStatus::parse("closed"), None);
    }
}
