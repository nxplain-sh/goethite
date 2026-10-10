//! DNSSEC validation in the recursor: building the chain of trust from the
//! root's trust anchors down, and checking each answer against it.
//!
//! The chain of trust is walked one label at a time, asking each signed
//! zone for its child's DS records: signed DS records lead to the child's
//! keys; a signed proof that a delegation has none makes everything below
//! it insecure; a signed proof that there is no delegation at a name keeps
//! the walk in the same zone. What each name was found to be is kept in
//! the infrastructure tables, so the walk is done once per zone, not per
//! query. Only signed proofs move a name out of a signed zone: a forged
//! or missing answer can make a name bogus, never insecure.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use goethite_proto::{Name, Record, RecordType, ResponseCode};
use tokio::time::Instant;
use tracing::warn;

use super::dnssec::{self, Checks, Denial, Security};
use super::infra::{self, Trust};
use super::{Budget, Found, RecurseError, Recursor};

/// How long a broken chain of trust is remembered.
const BOGUS_TTL: u32 = 60;

/// What validating one client query may still spend, and the time
/// signatures are checked at.
pub(super) struct Validation {
    checks: Checks,
    now: u32,
}

impl Validation {
    pub(super) fn new() -> Self {
        Self {
            checks: Checks::new(dnssec::MAX_CHECKS),
            now: unix_now(),
        }
    }

    /// A verification that failed: bogus, unless it was for want of
    /// checks, which proves nothing.
    fn failed<T>(&self, bogus: T) -> Result<T, RecurseError> {
        if self.checks.ran_out() {
            Err(RecurseError::Budget)
        } else {
            Ok(bogus)
        }
    }
}

/// The time as signatures count it: seconds since 1970, modulo 2^32.
fn unix_now() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    u32::try_from(secs & u64::from(u32::MAX)).unwrap_or(0)
}

/// What a signed zone says about one of its child names.
enum Step {
    /// A zone cut: the child zone's trust.
    Zone(Trust),
    /// No zone cut: the child is in the same zone.
    NotZone,
    /// The child does not exist, nor anything below it.
    Missing,
}

impl From<Denial> for Security {
    fn from(denial: Denial) -> Self {
        match denial {
            Denial::Proven => Self::Secure,
            Denial::Insecure => Self::Insecure,
            Denial::Unproven => Self::Bogus,
        }
    }
}

impl Recursor {
    /// Validates what a client query found, one zone's answer at a time:
    /// the least secure of them, with TTLs capped to what the signatures
    /// allow.
    pub(super) async fn validate(
        &self,
        segments: &mut [Found],
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<Security, RecurseError> {
        let mut security = Security::Secure;
        for segment in segments.iter_mut() {
            let result = if segment.records.is_empty() {
                self.validate_negative(segment, budget, v).await?
            } else {
                let positive = self.validate_positive(segment, budget, v).await?;
                if segment.rcode == ResponseCode::NX_DOMAIN {
                    // The chain ends in a name that does not exist: its
                    // denial needs proving too (RFC 6604).
                    let negative = self.validate_negative(segment, budget, v).await?;
                    positive.max(negative)
                } else {
                    positive
                }
            };
            security = security.max(result);
            if security == Security::Bogus {
                break;
            }
        }
        Ok(security)
    }

    /// Each RRset of an answer must be signed by a secure zone, or lie in
    /// an insecure one; a CNAME may also come from a signed DNAME.
    async fn validate_positive(
        &self,
        segment: &mut Found,
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<Security, RecurseError> {
        // Only RRSIGs, which are not signed themselves: nothing to vouch for.
        let mut security = None;
        let mut checked = Vec::with_capacity(segment.records.len());
        for mut rrset in dnssec::rrsets(&segment.records) {
            let Some(first) = rrset.first() else {
                continue;
            };
            let (owner, rtype) = (first.name().clone(), first.record_type());
            if rtype == RecordType::RRSIG {
                checked.extend(rrset);
                continue;
            }
            let evidence = &segment.evidence;
            let result =
                if let Some(signer) = dnssec::signer(evidence, &owner, rtype, &segment.zone) {
                    self.check_rrset(&mut rrset, &signer, evidence, budget, v)
                        .await?
                } else if let Some(dname) = (rtype == RecordType::CNAME)
                    .then(|| synthesizing(evidence, first))
                    .flatten()
                {
                    let mut dname = vec![dname.clone()];
                    match dnssec::signer(
                        evidence,
                        &owner_of(&dname),
                        RecordType::DNAME,
                        &segment.zone,
                    ) {
                        Some(signer) => {
                            self.check_rrset(&mut dname, &signer, evidence, budget, v)
                                .await?
                        }
                        None => self.unsigned(&owner, rtype, budget, v).await?,
                    }
                } else {
                    self.unsigned(&owner, rtype, budget, v).await?
                };
            checked.extend(rrset);
            if result == Security::Bogus {
                return Ok(Security::Bogus);
            }
            security = Some(security.map_or(result, |worst: Security| worst.max(result)));
        }
        segment.records = checked;
        Ok(security.unwrap_or(Security::Insecure))
    }

    /// A negative answer must come with signed proof from the zone that
    /// would hold the name, or lie in an insecure zone.
    async fn validate_negative(
        &self,
        segment: &mut Found,
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<Security, RecurseError> {
        let name = segment.name.clone();
        let qtype = segment.qtype;
        // DS records are held by the parent.
        let holder = if qtype == RecordType::DS {
            name.parent().unwrap_or_else(Name::root)
        } else {
            name.clone()
        };
        let evidence = &segment.evidence;
        let soa_signer = segment
            .soa
            .as_ref()
            .and_then(|soa| dnssec::signer(evidence, soa.name(), RecordType::SOA, &segment.zone));
        let signer = soa_signer
            .or_else(|| {
                evidence
                    .iter()
                    .filter(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3))
                    .find_map(|r| {
                        dnssec::signer(evidence, r.name(), r.record_type(), &segment.zone)
                    })
            })
            .filter(|signer| holder.is_within(signer));
        let Some(signer) = signer else {
            return self.unsigned(&name, qtype, budget, v).await;
        };
        let keys = match self.trust(&signer, budget, v).await? {
            Trust::Secure { zone, keys } if zone == signer => keys,
            Trust::Insecure => return Ok(Security::Insecure),
            // A signer that is no zone, or a broken chain.
            Trust::Secure { .. } | Trust::Bogus => return Ok(Security::Bogus),
        };
        if let Some(soa) = &mut segment.soa {
            let rrset = std::slice::from_ref(&*soa);
            let Some(verified) =
                dnssec::verify_rrset(rrset, evidence, &signer, &keys, v.now, &mut v.checks)
            else {
                return v.failed(Security::Bogus);
            };
            soa.set_ttl(soa.ttl().min(verified.ttl));
        }
        let (proofs, _) = dnssec::verified_proofs(evidence, &signer, &keys, v.now, &mut v.checks);
        if v.checks.ran_out() {
            return Err(RecurseError::Budget);
        }
        let denial = if segment.rcode == ResponseCode::NX_DOMAIN {
            if dnssec::nsec_nxdomain(&name, &proofs) {
                Denial::Proven
            } else {
                dnssec::nsec3_nxdomain(&signer, &name, &proofs)
            }
        } else if dnssec::nsec_nodata(&name, qtype, &proofs) {
            Denial::Proven
        } else {
            dnssec::nsec3_nodata(&signer, &name, qtype, &proofs)
        };
        Ok(denial.into())
    }

    /// An RRset signed by `signer`: secure if the zone is and a signature
    /// checks, and, for one from a wildcard, if the name provably does not
    /// exist; its TTLs capped to the signature's.
    async fn check_rrset(
        &self,
        rrset: &mut [Record],
        signer: &Name,
        evidence: &[Record],
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<Security, RecurseError> {
        let keys = match self.trust(signer, budget, v).await? {
            Trust::Secure { zone, keys } if zone == *signer => keys,
            Trust::Insecure => return Ok(Security::Insecure),
            // A signer that is no zone: whoever made the signature is not
            // who the chain of trust vouches for.
            Trust::Secure { .. } | Trust::Bogus => return Ok(Security::Bogus),
        };
        let Some(verified) =
            dnssec::verify_rrset(rrset, evidence, signer, &keys, v.now, &mut v.checks)
        else {
            return v.failed(Security::Bogus);
        };
        for record in rrset.iter_mut() {
            record.set_ttl(record.ttl().min(verified.ttl));
        }
        let (Some(encloser), Some(first)) = (verified.wildcard, rrset.first()) else {
            return Ok(Security::Secure);
        };
        let owner = first.name();
        let (proofs, _) = dnssec::verified_proofs(evidence, signer, &keys, v.now, &mut v.checks);
        if dnssec::nsec_wildcard(owner, &encloser, &proofs) {
            return Ok(Security::Secure);
        }
        let denial = dnssec::nsec3_wildcard(signer, owner, &encloser, &proofs);
        if denial == Denial::Unproven {
            return v.failed(Security::Bogus);
        }
        Ok(denial.into())
    }

    /// Unsigned data at `owner`: insecure if it lies in an unsigned zone,
    /// bogus in a signed one.
    async fn unsigned(
        &self,
        owner: &Name,
        rtype: RecordType,
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<Security, RecurseError> {
        let holder = if rtype == RecordType::DS {
            owner.parent().unwrap_or_else(Name::root)
        } else {
            owner.clone()
        };
        Ok(match self.trust(&holder, budget, v).await? {
            Trust::Insecure => Security::Insecure,
            Trust::Secure { .. } | Trust::Bogus => Security::Bogus,
        })
    }

    /// Where `name` stands in the chain of trust: the trust of the zone
    /// that holds it. Walks down from the closest name whose trust is
    /// known, one label at a time.
    pub(super) async fn trust(
        &self,
        name: &Name,
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<Trust, RecurseError> {
        let (mut at, mut trust, mut expires) =
            if let Some(known) = self.infra.closest_trust(name, Instant::now()) {
                known
            } else {
                let (trust, expires) = self.root_trust(budget, v).await?;
                self.infra.set_trust(Name::root(), trust.clone(), expires);
                (Name::root(), trust, expires)
            };
        loop {
            let Trust::Secure { zone, keys } = &trust else {
                return Ok(trust);
            };
            let Some(child) = name
                .suffix(at.label_count().saturating_add(1))
                .filter(|_| at.label_count() < name.label_count())
            else {
                return Ok(trust);
            };
            let (step, ttl) = self.step_down(zone, keys, &child, budget, v).await?;
            let now = Instant::now();
            let child_expires = infra::expiry(ttl, now).min(expires);
            let missing = matches!(step, Step::Missing);
            match step {
                Step::Zone(Trust::Bogus) => {
                    trust = Trust::Bogus;
                    expires = infra::expiry(BOGUS_TTL, now);
                }
                Step::Zone(next) => {
                    trust = next;
                    expires = child_expires;
                }
                Step::NotZone | Step::Missing => expires = child_expires,
            }
            self.infra.set_trust(child.clone(), trust.clone(), expires);
            if missing {
                return Ok(trust);
            }
            at = child;
        }
    }

    /// The root zone's keys, anchored in the trust anchors.
    async fn root_trust(
        &self,
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<(Trust, Instant), RecurseError> {
        let root = Name::root();
        let found = Box::pin(self.lookup(&root, RecordType::DNSKEY, budget, 0)).await?;
        let mut dnskeys = found.records;
        dnskeys.extend(found.evidence);
        let now = Instant::now();
        if let Some((keys, ttl)) =
            dnssec::keys_from_ds(&root, &self.anchors, &dnskeys, v.now, &mut v.checks)
        {
            let trust = Trust::Secure {
                zone: root,
                keys: keys.into(),
            };
            return Ok((trust, infra::expiry(ttl, now)));
        }
        let bogus = v.failed(Trust::Bogus)?;
        warn!("the root zone's keys do not match the trust anchors");
        Ok((bogus, infra::expiry(BOGUS_TTL, now)))
    }

    /// Asks the signed zone `zone` for `child`'s DS records: what they and
    /// their proofs say, and for how long.
    async fn step_down(
        &self,
        zone: &Name,
        keys: &Arc<[Record]>,
        child: &Name,
        budget: &mut Budget,
        v: &mut Validation,
    ) -> Result<(Step, u32), RecurseError> {
        let bogus = || (Step::Zone(Trust::Bogus), BOGUS_TTL);
        let found = Box::pin(self.lookup(child, RecordType::DS, budget, 0)).await?;
        let ds: Vec<Record> = found
            .records
            .iter()
            .filter(|r| r.record_type() == RecordType::DS && r.name() == child)
            .cloned()
            .collect();
        if !ds.is_empty() {
            let Some(verified) =
                dnssec::verify_rrset(&ds, &found.evidence, zone, keys, v.now, &mut v.checks)
            else {
                return v.failed(bogus());
            };
            if dnssec::usable_ds(&ds).is_empty() {
                // Only algorithms or digests not supported: insecure (RFC
                // 4035 5.2).
                return Ok((Step::Zone(Trust::Insecure), verified.ttl));
            }
            let found = Box::pin(self.lookup(child, RecordType::DNSKEY, budget, 0)).await?;
            let mut dnskeys = found.records;
            dnskeys.extend(found.evidence);
            return match dnssec::keys_from_ds(child, &ds, &dnskeys, v.now, &mut v.checks) {
                Some((child_keys, ttl)) => Ok((
                    Step::Zone(Trust::Secure {
                        zone: child.clone(),
                        keys: child_keys.into(),
                    }),
                    ttl.min(verified.ttl),
                )),
                None => v.failed(bogus()),
            };
        }
        if !found.records.is_empty() {
            // A CNAME: no zone cut, and nothing below it.
            let rrset: Vec<Record> = found
                .records
                .iter()
                .filter(|r| r.name() == child)
                .cloned()
                .collect();
            return match dnssec::verify_rrset(
                &rrset,
                &found.evidence,
                zone,
                keys,
                v.now,
                &mut v.checks,
            ) {
                Some(verified) => Ok((Step::Missing, verified.ttl)),
                None => v.failed(bogus()),
            };
        }
        let (proofs, ttl) =
            dnssec::verified_proofs(&found.evidence, zone, keys, v.now, &mut v.checks);
        if v.checks.ran_out() {
            return Err(RecurseError::Budget);
        }
        let step = if found.rcode == ResponseCode::NX_DOMAIN {
            if dnssec::nsec_nxdomain(child, &proofs) {
                Step::Missing
            } else {
                match dnssec::nsec3_nxdomain(zone, child, &proofs) {
                    Denial::Proven => Step::Missing,
                    Denial::Insecure => Step::Zone(Trust::Insecure),
                    Denial::Unproven => return Ok(bogus()),
                }
            }
        } else {
            match dnssec::ds_denial(zone, child, &proofs) {
                Denial::Proven | Denial::Insecure => Step::Zone(Trust::Insecure),
                Denial::Unproven if dnssec::nsec_nodata(child, RecordType::DS, &proofs) => {
                    Step::NotZone
                }
                Denial::Unproven => {
                    match dnssec::nsec3_nodata(zone, child, RecordType::DS, &proofs) {
                        Denial::Proven => Step::NotZone,
                        Denial::Insecure => Step::Zone(Trust::Insecure),
                        Denial::Unproven => return Ok(bogus()),
                    }
                }
            }
        };
        Ok((step, ttl))
    }
}

/// The DNAME in `evidence` that synthesized `cname`, if any.
fn synthesizing<'a>(evidence: &'a [Record], cname: &Record) -> Option<&'a Record> {
    evidence
        .iter()
        .filter(|r| r.record_type() == RecordType::DNAME)
        .find(|dname| dnssec::synthesized(cname, dname))
}

fn owner_of(rrset: &[Record]) -> Name {
    rrset
        .first()
        .map_or_else(Name::root, |record| record.name().clone())
}
