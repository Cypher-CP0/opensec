use crate::Id;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizationCheck {
    TenantIsolation {
        identity_a_ref: Id,
        identity_b_ref: Id,
        tenant_a: Id,
        tenant_b: Id,
        export_a: Id,
        export_b: Id,
    },
    ObjectAuthorization {
        identity_a_ref: Id,
        identity_b_ref: Id,
        object: ObjectCheck,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectCheck {
    #[schemars(length(min = 1, max = 512))]
    path_template: String,
    resource_a: Id,
    resource_b: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_a: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_b: Option<Id>,
    response: ObjectResponse,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectResponse {
    #[schemars(length(min = 2, max = 256))]
    resource_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_id: Option<String>,
    #[schemars(length(min = 2, max = 256))]
    protected_value: String,
}
fn pair(a: &Id, b: &Id) -> Result<(), String> {
    a.validate()?;
    b.validate()?;
    if a.0 == b.0 {
        return Err("authorization controls must be distinct".into());
    }
    Ok(())
}
fn pointer(s: &str) -> bool {
    if !(2..=256).contains(&s.len()) || !s.starts_with('/') || s[1..].split('/').count() > 16 {
        return false;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] < 32 || bytes[i] == 127 {
            return false;
        }
        if bytes[i] == b'~' {
            i += 1;
            if i >= bytes.len() || (bytes[i] != b'0' && bytes[i] != b'1') {
                return false;
            }
        }
        i += 1;
    }
    true
}
pub(crate) fn template(s: &str) -> bool {
    if s.len() > 512 || !s.starts_with('/') || s.matches("{id}").count() != 1 {
        return false;
    }
    let parts: Vec<_> = s[1..].split('/').collect();
    parts.len() <= 32
        && parts.iter().all(|p| {
            *p == "{id}"
                || (!p.is_empty()
                    && *p != "."
                    && *p != ".."
                    && p.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
        })
}
impl AuthorizationCheck {
    pub(crate) fn paths(&self) -> Vec<String> {
        let (template, a, b) = match self {
            Self::TenantIsolation {
                export_a, export_b, ..
            } => ("/exports/{id}", &export_a.0, &export_b.0),
            Self::ObjectAuthorization { object, .. } => (
                object.path_template.as_str(),
                &object.resource_a.0,
                &object.resource_b.0,
            ),
        };
        vec![template.replace("{id}", a), template.replace("{id}", b)]
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        match self {
            Self::TenantIsolation {
                identity_a_ref,
                identity_b_ref,
                tenant_a,
                tenant_b,
                export_a,
                export_b,
            } => {
                pair(identity_a_ref, identity_b_ref)?;
                pair(tenant_a, tenant_b)?;
                pair(export_a, export_b)
            }
            Self::ObjectAuthorization {
                identity_a_ref,
                identity_b_ref,
                object: o,
            } => {
                pair(identity_a_ref, identity_b_ref)?;
                pair(&o.resource_a, &o.resource_b)?;
                if !template(&o.path_template)
                    || !pointer(&o.response.resource_id)
                    || !pointer(&o.response.protected_value)
                    || o.response.resource_id == o.response.protected_value
                {
                    return Err("invalid object endpoint or response selectors".into());
                }
                match (&o.response.owner_id, &o.owner_a, &o.owner_b) {
                    (None, None, None) => Ok(()),
                    (Some(p), Some(a), Some(b))
                        if pointer(p)
                            && *p != o.response.resource_id
                            && *p != o.response.protected_value =>
                    {
                        pair(a, b)
                    }
                    _ => Err("owner controls require a distinct selector and two owner IDs".into()),
                }
            }
        }
    }
}
