use std::collections::{BTreeMap, BTreeSet};
use serde::{Serialize, Deserialize};
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Permission(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoleId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub permissions: BTreeSet<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub roles: BTreeSet<RoleId>,
}

/// In-memory RBAC manager; can later be backed by DB or external IdP.
#[derive(Debug, Default)]
pub struct RbacManager {
    roles: BTreeMap<RoleId, Role>,
    users: BTreeMap<UserId, User>,
}

impl RbacManager {
    pub fn new() -> Self { Self::default() }

    pub fn upsert_role(&mut self, role: Role) {
        self.roles.insert(role.id.clone(), role);
    }

    pub fn upsert_user(&mut self, user: User) {
        self.users.insert(user.id.clone(), user);
    }

    pub fn check(&self, user: &UserId, perm: &Permission) -> Result<bool> {
        let user = match self.users.get(user) {
            Some(u) => u,
            None => return Ok(false),
        };
        for rid in &user.roles {
            if let Some(role) = self.roles.get(rid) {
                if role.permissions.contains(perm) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
