// Some rcan capabilities

// Nicked from
// https://github.com/n0-computer/iroh-services/blob/main/src/caps.rs
//
// PERHAPS rewrite rcan.

use anyhow::Result;
// use ed25519_dalek::pkcs8::spki::der::pem::decode;
use iroh::{EndpointId, SecretKey};
use rcan::{Capability, Expires, Rcan};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::Duration};

/// A set of capabilities
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Serialize, Deserialize)]
pub struct CapSet<C: Capability + Ord>(BTreeSet<C>);

impl<C: Capability + Ord> Default for CapSet<C> {
    fn default() -> Self {
        Self(BTreeSet::new())
    }
}

impl<C: Capability + Ord> CapSet<C> {
    pub fn new(set: impl IntoIterator<Item = impl Into<C>>) -> Self {
        Self(BTreeSet::from_iter(set.into_iter().map(Into::into)))
    }

    pub fn iter(&self) -> impl Iterator<Item = &'_ C> + '_ {
        self.0.iter()
    }
}

impl<C: Capability + Ord> Capability for CapSet<C> {
    fn permits(&self, other: &Self) -> bool {
        other
            .iter()
            .all(|other_cap| self.iter().any(|self_cap| self_cap.permits(other_cap)))
    }
}

// The actual capability
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Ord, Serialize, Deserialize)]
pub enum Cap {
    All,
    Sign,
    Issue,
    Revoke,
    Status,
}

impl Capability for Cap {
    fn permits(&self, other: &Self) -> bool {
        match (self, other) {
            (Cap::All, _) => true,
            (Cap::Sign, Cap::Sign) => true,
            (Cap::Issue, Cap::Issue) => true,
            (Cap::Revoke, Cap::Revoke) => true,
            (Cap::Status, Cap::Status) => true,
            (_, _) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Caps {
    V0(CapSet<Cap>),
}

impl std::ops::Deref for Caps {
    type Target = CapSet<Cap>;

    fn deref(&self) -> &Self::Target {
        let Self::V0(slf) = self;
        slf
    }
}

impl Capability for Caps {
    fn permits(&self, other: &Self) -> bool {
        let Self::V0(slf) = self;
        let Self::V0(other) = other;
        slf.permits(other)
    }
}

impl Caps {
    pub fn new(caps: impl IntoIterator<Item = impl Into<Cap>>) -> Self {
        Self::V0(CapSet::new(caps))
    }

    pub fn all() -> Self {
        Self::new([Cap::All])
    }

    pub fn sign() -> Self {
        Self::new([Cap::Sign])
    }

    pub fn issue() -> Self {
        Self::new([Cap::Sign, Cap::Issue])
    }

    pub fn status() -> Self {
        Self::new([Cap::Status])
    }

    pub fn as_text(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn make(
        &self,
        secret_key: &SecretKey,
        target: EndpointId,
        duration: Duration,
    ) -> Result<Rcan<Caps>> {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&secret_key.to_bytes());
        let audience = target.as_verifying_key();
        let can = Rcan::issuing_builder(&issuer, audience, self.clone())
            .sign(Expires::valid_for(duration));
        // .sign(Expires::valid_for(Duration::from_secs(120)));
        Ok(can)
    }

    pub fn encoded(
        &self,
        secret_key: &SecretKey,
        target: EndpointId,
        duration: Duration,
    ) -> Result<String> {
        let rc = self.make(secret_key, target, duration)?;
        let ser = rc.encode();
        let mut encoded = data_encoding::BASE32_NOPAD.encode(&ser);
        encoded = encoded.to_lowercase();
        Ok(encoded)
    }

    pub fn decode(input: Vec<u8>) -> Result<Rcan<Caps>> {
        let upper = input.to_ascii_uppercase();
        let decoded = data_encoding::BASE32_NOPAD.decode(&upper)?;
        let deser = Rcan::<Caps>::decode(&decoded)?;
        Ok(deser)
    }
}
