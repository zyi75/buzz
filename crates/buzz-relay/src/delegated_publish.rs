use nostr::{Event, PublicKey};
use serde::Deserialize;

const DELEGATED_KIND: u32 = 30078;

/// One explicit delegated-publish grant.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegatedPublishGrant {
    publisher_pubkey: String,
    author_pubkey: String,
    kind: u32,
}

/// Fail-closed delegated-publish grants. An empty ACL authorizes nothing.
#[derive(Debug, Clone, Default)]
pub struct DelegatedPublishAcl {
    grants: Vec<DelegatedPublishGrant>,
}

/// Why an event may not be published by the authenticated transport identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishAuthorizationError {
    /// The original event ID or signature is invalid.
    InvalidEvent(String),
    /// The publisher is neither the author nor covered by an explicit grant.
    PublisherNotAuthorized,
}

/// Verify the original event first, then authorize self-publish or an explicit delegation.
pub fn validate_event_publish(
    acl: &DelegatedPublishAcl,
    publisher: &PublicKey,
    event: &Event,
) -> Result<(), PublishAuthorizationError> {
    buzz_core::verification::verify_event(event)
        .map_err(|error| PublishAuthorizationError::InvalidEvent(error.to_string()))?;
    if event.pubkey == *publisher || acl.authorizes(publisher, event) {
        Ok(())
    } else {
        Err(PublishAuthorizationError::PublisherNotAuthorized)
    }
}

impl DelegatedPublishAcl {
    /// Parse a JSON array of explicit grants.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut grants: Vec<DelegatedPublishGrant> = serde_json::from_str(raw)
            .map_err(|error| format!("invalid delegated publish ACL: {error}"))?;
        for grant in &mut grants {
            grant.publisher_pubkey = normalize_pubkey(&grant.publisher_pubkey)?;
            grant.author_pubkey = normalize_pubkey(&grant.author_pubkey)?;
            if grant.kind != DELEGATED_KIND {
                return Err(
                    "invalid delegated publish ACL: every grant requires author and kind 30078"
                        .into(),
                );
            }
        }
        Ok(Self { grants })
    }

    /// Return true only when one grant exactly covers publisher, author, and the v0.1 kind.
    pub fn authorizes(&self, publisher: &PublicKey, event: &Event) -> bool {
        let publisher = publisher.to_hex();
        let author = event.pubkey.to_hex();
        let kind = buzz_core::kind::event_kind_u32(event);
        self.grants.iter().any(|grant| {
            grant.publisher_pubkey.eq_ignore_ascii_case(&publisher)
                && grant.author_pubkey.eq_ignore_ascii_case(&author)
                && grant.kind == DELEGATED_KIND
                && kind == DELEGATED_KIND
        })
    }
}

fn normalize_pubkey(value: &str) -> Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid delegated publish ACL: malformed pubkey".into());
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use nostr::{EventBuilder, Keys, Kind};

    use super::{validate_event_publish, DelegatedPublishAcl, PublishAuthorizationError};

    #[test]
    fn authorized_node_can_transport_owner_event_in_exact_scope() {
        let publisher = Keys::generate();
        let owner = Keys::generate();
        let acl = DelegatedPublishAcl::parse(&format!(
            r#"[{{"publisher_pubkey":"{}","author_pubkey":"{}","kind":30078}}]"#,
            publisher.public_key(),
            owner.public_key(),
        ))
        .expect("valid ACL");
        let event = EventBuilder::new(Kind::Custom(30078), "{}")
            .sign_with_keys(&owner)
            .expect("signed event");

        assert!(acl.authorizes(&publisher.public_key(), &event));
    }

    #[test]
    fn delegation_denies_every_ungranted_dimension_and_defaults_to_deny() {
        let publisher = Keys::generate();
        let owner = Keys::generate();
        let other_publisher = Keys::generate();
        let other_owner = Keys::generate();
        let acl = DelegatedPublishAcl::parse(&format!(
            r#"[{{"publisher_pubkey":"{}","author_pubkey":"{}","kind":30078}}]"#,
            publisher.public_key(),
            owner.public_key(),
        ))
        .expect("valid ACL");
        let event = |keys: &Keys, kind: u16| {
            EventBuilder::new(Kind::Custom(kind), "{}")
                .sign_with_keys(keys)
                .expect("signed event")
        };

        assert!(!DelegatedPublishAcl::default()
            .authorizes(&publisher.public_key(), &event(&owner, 30078),));
        assert!(!acl.authorizes(&other_publisher.public_key(), &event(&owner, 30078),));
        assert!(!acl.authorizes(&publisher.public_key(), &event(&other_owner, 30078),));
        assert!(!acl.authorizes(&publisher.public_key(), &event(&owner, 30079),));
    }

    #[test]
    fn malformed_or_broadened_configuration_is_rejected() {
        assert!(DelegatedPublishAcl::parse("not-json").is_err());
        assert!(DelegatedPublishAcl::parse("{}").is_err());
        assert!(DelegatedPublishAcl::parse(
            r#"[{"publisher_pubkey":"bad","author_pubkey":"bad","kind":30078}]"#,
        )
        .is_err());
        assert!(DelegatedPublishAcl::parse(
            r#"[{"publisher_pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","author_pubkey":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":30079}]"#,
        )
        .is_err());
    }

    #[test]
    fn invalid_original_signature_is_rejected_before_delegation() {
        let publisher = Keys::generate();
        let owner = Keys::generate();
        let acl = DelegatedPublishAcl::parse(&format!(
            r#"[{{"publisher_pubkey":"{}","author_pubkey":"{}","kind":30078}}]"#,
            publisher.public_key(),
            owner.public_key(),
        ))
        .expect("valid ACL");
        let mut event = EventBuilder::new(Kind::Custom(30078), "original")
            .sign_with_keys(&owner)
            .expect("signed event");
        event.content = "mutated".to_string();

        assert!(matches!(
            validate_event_publish(&acl, &publisher.public_key(), &event),
            Err(PublishAuthorizationError::InvalidEvent(_))
        ));
    }
}
