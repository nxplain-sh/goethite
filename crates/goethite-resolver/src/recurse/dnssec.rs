//! DNSSEC validation's pure parts (RFC 4035, RFC 5155, RFC 6840): checking
//! an RRset's signatures against a zone's keys, a zone's keys against its
//! DS records, and the proofs that a name or type does not exist. No I/O:
//! the recursor fetches the records and keeps the chain of trust.
//!
//! Everything is bounded against hostile zones (KeyTrap, CVE-2023-50387,
//! and NSEC3 hash floods): every signature check and every DS digest spends
//! from a budget for the client's query, at most [`MAX_KEYS_PER_TAG`] keys
//! are tried for one key tag and [`MAX_SIGS_PER_RRSET`] signatures for one
//! RRset, keys are matched to DS records by tag and algorithm before any
//! digest, and NSEC3 proofs with more than [`MAX_NSEC3_ITERATIONS`]
//! iterations count as insecure (RFC 9276) and are never hashed.

use std::cmp::Ordering;
use std::collections::HashMap;

use goethite_proto::dnssec::{
    self, Dnskey, Nsec, Nsec3, Rrsig, algorithm_supported, digest_supported,
};
use goethite_proto::{Name, Record, RecordType};

/// The most signature checks for one client query.
pub(super) const MAX_CHECKS: u32 = 64;
/// The most keys tried for one key tag (several keys may share one).
pub(super) const MAX_KEYS_PER_TAG: usize = 4;
/// The most signatures tried for one RRset.
pub(super) const MAX_SIGS_PER_RRSET: usize = 8;
/// NSEC3 proofs with more iterations count as insecure (RFC 9276).
pub(super) const MAX_NSEC3_ITERATIONS: u16 = 150;
/// The most NSEC3 hashes computed for one proof.
const MAX_HASHES: usize = 64;
/// How far a signature's times may be off, at most: clocks are not exact.
const MAX_SKEW: u32 = 3_600;

/// What validation found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Security {
    /// Signed, and every signature checked: the AD bit.
    Secure,
    /// Not signed, or in a part of the DNS that is provably unsigned.
    Insecure,
    /// Should be signed but is not, or the signatures do not check: an
    /// answer no one may get.
    Bogus,
}

/// Signature checks left for a client's query.
#[derive(Debug)]
pub(super) struct Checks {
    left: u32,
    ran_out: bool,
}

impl Checks {
    /// A budget of `checks` signature checks.
    pub(super) fn new(checks: u32) -> Self {
        Self {
            left: checks,
            ran_out: false,
        }
    }

    /// Checks left.
    pub(super) fn left(&self) -> u32 {
        self.left
    }

    /// Whether a check was refused for want of budget: then a failed
    /// verification proves nothing about the data.
    pub(super) fn ran_out(&self) -> bool {
        self.ran_out
    }

    fn spend(&mut self) -> bool {
        if let Some(left) = self.left.checked_sub(1) {
            self.left = left;
            true
        } else {
            self.ran_out = true;
            false
        }
    }
}

/// `a` is at or before `b` in serial number arithmetic (RFC 1982), as
/// signature times are.
fn serial_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}

/// Whether `rrsig` is valid at `now`, with some slack for clocks.
fn in_time(rrsig: &Rrsig, now: u32) -> bool {
    let validity = rrsig.expiration.wrapping_sub(rrsig.inception);
    let skew = (validity / 10).min(MAX_SKEW);
    serial_le(rrsig.inception, now.wrapping_add(skew))
        && serial_le(now.wrapping_sub(skew), rrsig.expiration)
}

/// The keys of a zone that may sign: zone keys of a supported algorithm,
/// not revoked.
pub(super) fn usable_keys(dnskeys: &[Record]) -> Vec<Record> {
    dnskeys
        .iter()
        .filter(|record| {
            record.dnskey().is_some_and(|key: Dnskey| {
                key.zone_key() && !key.revoked() && algorithm_supported(key.algorithm)
            })
        })
        .cloned()
        .collect()
}

/// A checked RRset: how long it may be kept, and, for one synthesized from
/// a wildcard, the wildcard's parent (the closest encloser).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Verified {
    /// The TTL the records may have at most: the signature's original TTL
    /// and the time left until it expires.
    pub ttl: u32,
    /// For an answer from a wildcard, the name the wildcard is below.
    pub wildcard: Option<Name>,
}

/// Checks `rrset` (one owner and type) against `sigs` (any RRSIGs) with
/// `keys`, the usable keys of `signer`: at least one RRSIG by `signer`
/// covering the type, in time and labelled consistently, must verify.
pub(super) fn verify_rrset(
    rrset: &[Record],
    sigs: &[Record],
    signer: &Name,
    keys: &[Record],
    now: u32,
    checks: &mut Checks,
) -> Option<Verified> {
    let first = rrset.first()?;
    let owner = first.name();
    let labels = owner.labels().filter(|label| *label != b"*").count();
    // The key tag of each key is computed once, not per signature.
    let keys: Vec<(&Record, Dnskey)> = keys
        .iter()
        .filter_map(|key| Some((key, key.dnskey()?)))
        .collect();
    let candidates = sigs.iter().filter_map(|record| {
        let rrsig = record.rrsig()?;
        (record.name() == owner
            && rrsig.type_covered == first.record_type()
            && &rrsig.signer == signer
            && owner.is_within(signer)
            && usize::from(rrsig.labels) <= labels
            && algorithm_supported(rrsig.algorithm)
            && in_time(&rrsig, now))
        .then_some((record, rrsig))
    });
    for (record, rrsig) in candidates.take(MAX_SIGS_PER_RRSET) {
        let matching = keys
            .iter()
            .filter(|(_, key)| key.key_tag == rrsig.key_tag && key.algorithm == rrsig.algorithm);
        for (key, _) in matching.take(MAX_KEYS_PER_TAG) {
            if !checks.spend() {
                return None;
            }
            if dnssec::verify(rrset, record, key).is_ok() {
                // Accepted just after expiring, within the clock skew:
                // nothing left to keep.
                let left = if serial_le(now, rrsig.expiration) {
                    rrsig.expiration.wrapping_sub(now)
                } else {
                    0
                };
                let wildcard = (usize::from(rrsig.labels) < labels)
                    .then(|| owner.suffix(usize::from(rrsig.labels)))
                    .flatten();
                return Some(Verified {
                    ttl: rrsig.original_ttl.min(left),
                    wildcard,
                });
            }
        }
    }
    None
}

/// The usable keys of `zone`, if one that a usable DS of `ds` is a digest
/// of signs the DNSKEY RRset in `dnskeys` (which holds its RRSIGs too):
/// the keys, and how long they may be kept. No usable DS at all (an
/// insecure zone, RFC 4035 5.2) is told apart by [`usable_ds`].
pub(super) fn keys_from_ds(
    zone: &Name,
    ds: &[Record],
    dnskeys: &[Record],
    now: u32,
    checks: &mut Checks,
) -> Option<(Vec<Record>, u32)> {
    let usable = usable_ds(ds);
    let keys = usable_keys(dnskeys);
    // DS records by the key tag and algorithm they name: a key is hashed
    // only against DS records that claim it, and each digest spends a check
    // (KeyTrap, CVE-2023-50387).
    let mut by_tag: HashMap<(u16, u8), Vec<&Record>> = HashMap::new();
    for record in &usable {
        if let Some(ds) = record.ds() {
            by_tag
                .entry((ds.key_tag, ds.algorithm))
                .or_default()
                .push(record);
        }
    }
    let mut anchored = Vec::new();
    for key in &keys {
        if anchored.len() >= MAX_KEYS_PER_TAG {
            break;
        }
        let Some(fields) = key.dnskey() else {
            continue;
        };
        let Some(candidates) = by_tag.get(&(fields.key_tag, fields.algorithm)) else {
            continue;
        };
        for record in candidates {
            if !checks.spend() {
                return None;
            }
            if dnssec::ds_matches(record, key, zone) {
                anchored.push(key.clone());
                break;
            }
        }
    }
    let rrset: Vec<Record> = dnskeys
        .iter()
        .filter(|record| record.record_type() == RecordType::DNSKEY && record.name() == zone)
        .cloned()
        .collect();
    let verified = verify_rrset(&rrset, dnskeys, zone, &anchored, now, checks)?;
    Some((keys, verified.ttl))
}

/// The DS records that can be used: supported algorithm and digest; and
/// when there is a SHA-256 one, no SHA-1 ones (RFC 4509, section 3).
pub(super) fn usable_ds(ds: &[Record]) -> Vec<Record> {
    let supported: Vec<&Record> = ds
        .iter()
        .filter(|record| {
            record.ds().is_some_and(|d| {
                algorithm_supported(d.algorithm) && digest_supported(d.digest_type)
            })
        })
        .collect();
    let strong = supported
        .iter()
        .any(|record| record.ds().is_some_and(|d| d.digest_type != 1));
    supported
        .into_iter()
        .filter(|record| !strong || record.ds().is_some_and(|d| d.digest_type != 1))
        .cloned()
        .collect()
}

/// What denial-of-existence records prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Denial {
    /// The name or type does not exist.
    Proven,
    /// It may lie in an unsigned delegation (NSEC3 opt-out), or the proof
    /// is too costly to check: treat as insecure.
    Insecure,
    /// Nothing is proven.
    Unproven,
}

/// Whether `owner`'s NSEC covers `name`: `owner < name < next` in
/// canonical order, the last NSEC of a zone wrapping round to the apex.
fn nsec_covers(owner: &Name, nsec: &Nsec, name: &Name) -> bool {
    let after_owner = owner.canonical_cmp(name) == Ordering::Less;
    let before_next = name.canonical_cmp(&nsec.next) == Ordering::Less;
    if owner.canonical_cmp(&nsec.next) == Ordering::Less {
        after_owner && before_next
    } else {
        // The last NSEC: its next name is the apex.
        after_owner || before_next
    }
}

/// An NSEC at a delegation from the parent's side: NS without SOA. It
/// proves nothing about names below the delegation (RFC 6840, 4.1).
fn delegation(nsec: &Nsec) -> bool {
    nsec.types.contains(&RecordType::NS) && !nsec.types.contains(&RecordType::SOA)
}

fn nsecs(proof: &[Record]) -> impl Iterator<Item = (&Name, Nsec)> {
    proof
        .iter()
        .filter_map(|record| Some((record.name(), record.nsec()?)))
}

/// The NSEC that covers `name` without being an ancestor delegation.
fn covering_nsec<'a>(proof: &'a [Record], name: &Name) -> Option<(&'a Name, Nsec)> {
    nsecs(proof).find(|(owner, nsec)| {
        nsec_covers(owner, nsec, name)
            && !(name.is_within(owner)
                && (delegation(nsec) || nsec.types.contains(&RecordType::DNAME)))
    })
}

/// The longest common ancestor of two names, and of `name`'s ancestors the
/// closest encloser an NSEC covering `name` implies.
fn common_ancestor(a: &Name, b: &Name) -> Option<Name> {
    let shared = a
        .labels()
        .rev()
        .zip(b.labels().rev())
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count();
    a.suffix(shared)
}

/// `*.name`.
fn wildcard_of(name: &Name) -> Option<Name> {
    Name::from_labels(std::iter::once(&b"*"[..]).chain(name.labels())).ok()
}

/// NSEC proof that `name` does not exist (NXDOMAIN, RFC 4035 3.1.3.2): an
/// NSEC covers it, and one covers the wildcard at its closest encloser.
pub(super) fn nsec_nxdomain(name: &Name, proof: &[Record]) -> bool {
    let Some((owner, nsec)) = covering_nsec(proof, name) else {
        return false;
    };
    let encloser = [
        common_ancestor(name, owner),
        common_ancestor(name, &nsec.next),
    ]
    .into_iter()
    .flatten()
    .max_by_key(Name::label_count);
    let Some(wildcard) = encloser.as_ref().and_then(wildcard_of) else {
        return false;
    };
    covering_nsec(proof, &wildcard).is_some()
}

/// NSEC proof that `name` has no `qtype` records (NODATA, RFC 4035
/// 3.1.3.1): an NSEC at `name` without the type or a CNAME, where for a DS
/// question the parent's NSEC at a delegation counts and the child's apex
/// does not; an NSEC covering `name` whose next name is below it (an empty
/// non-terminal); or `name` covered and the wildcard at its closest
/// encloser without the type (a wildcard NODATA, RFC 4035 3.1.3.4).
pub(super) fn nsec_nodata(name: &Name, qtype: RecordType, proof: &[Record]) -> bool {
    let without =
        |nsec: &Nsec| !nsec.types.contains(&qtype) && !nsec.types.contains(&RecordType::CNAME);
    let at_name = nsecs(proof).any(|(owner, nsec)| {
        owner == name
            && without(&nsec)
            && (qtype == RecordType::DS || !delegation(&nsec))
            && (qtype != RecordType::DS || !nsec.types.contains(&RecordType::SOA))
    });
    if at_name {
        return true;
    }
    let Some((owner, nsec)) = covering_nsec(proof, name) else {
        return false;
    };
    if nsec.next.is_within(name) && nsec.next != *name {
        return true;
    }
    let encloser = [
        common_ancestor(name, owner),
        common_ancestor(name, &nsec.next),
    ]
    .into_iter()
    .flatten()
    .max_by_key(Name::label_count);
    let Some(wildcard) = encloser.as_ref().and_then(wildcard_of) else {
        return false;
    };
    qtype != RecordType::DS
        && nsecs(proof).any(|(owner, nsec)| *owner == wildcard && without(&nsec))
}

/// NSEC proof for an answer synthesized from a wildcard: `name` itself
/// does not exist.
pub(super) fn nsec_wildcard(name: &Name, proof: &[Record]) -> bool {
    covering_nsec(proof, name).is_some()
}

/// The NSEC3 records of a proof, all with the same parameters as the
/// first, which must be SHA-1 with at most [`MAX_NSEC3_ITERATIONS`].
struct Nsec3Set {
    records: Vec<(Vec<u8>, Nsec3)>,
    salt: Vec<u8>,
    iterations: u16,
    hashes: usize,
}

enum Nsec3Params {
    Usable(Nsec3Set),
    TooCostly,
    None,
}

fn nsec3_set(zone: &Name, proof: &[Record]) -> Nsec3Params {
    let records: Vec<(Vec<u8>, Nsec3)> = proof
        .iter()
        .filter_map(|record| {
            let nsec3 = record.nsec3()?;
            let owner = record.name();
            // The owner is one hashed label below the zone apex.
            (owner.parent().as_ref() == Some(zone))
                .then(|| Some((dnssec::nsec3_owner_hash(owner)?, nsec3)))
                .flatten()
        })
        .collect();
    let Some((_, first)) = records.first() else {
        return Nsec3Params::None;
    };
    if first.hash_algorithm != 1 {
        return Nsec3Params::None;
    }
    if first.iterations > MAX_NSEC3_ITERATIONS {
        return Nsec3Params::TooCostly;
    }
    let (salt, iterations) = (first.salt.clone(), first.iterations);
    Nsec3Params::Usable(Nsec3Set {
        records: records
            .into_iter()
            .filter(|(_, n)| n.hash_algorithm == 1 && n.salt == salt && n.iterations == iterations)
            .collect(),
        salt,
        iterations,
        hashes: 0,
    })
}

impl Nsec3Set {
    fn hash(&mut self, name: &Name) -> Option<Vec<u8>> {
        if self.hashes >= MAX_HASHES {
            return None;
        }
        self.hashes = self.hashes.saturating_add(1);
        dnssec::nsec3_hash(name, &self.salt, self.iterations)
    }

    /// The NSEC3 whose owner is `name`'s hash.
    fn matching(&mut self, name: &Name) -> Option<&Nsec3> {
        let hash = self.hash(name)?;
        self.records
            .iter()
            .find(|(owner, _)| *owner == hash)
            .map(|(_, nsec3)| nsec3)
    }

    /// The NSEC3 whose span covers `name`'s hash.
    fn covering(&mut self, name: &Name) -> Option<&Nsec3> {
        let hash = self.hash(name)?;
        self.records
            .iter()
            .find(|(owner, nsec3)| {
                let next = &nsec3.next_hashed;
                if owner < next {
                    owner < &hash && &hash < next
                } else {
                    owner < &hash || &hash < next
                }
            })
            .map(|(_, nsec3)| nsec3)
    }

    /// The closest encloser proof (RFC 5155 8.3): the longest ancestor of
    /// `name` within `zone` that exists, and the NSEC3 covering the next
    /// closer name below it.
    fn closest_encloser(&mut self, zone: &Name, name: &Name) -> Option<(Name, bool)> {
        let top = zone.label_count();
        for labels in (top..name.label_count()).rev() {
            let encloser = name.suffix(labels)?;
            let Some(matched) = self.matching(&encloser) else {
                continue;
            };
            // An ancestor delegation or a DNAME proves nothing below it.
            if (matched.types.contains(&RecordType::NS)
                && !matched.types.contains(&RecordType::SOA))
                || matched.types.contains(&RecordType::DNAME)
            {
                return None;
            }
            let next_closer = name.suffix(labels.saturating_add(1))?;
            let opt_out = self.covering(&next_closer)?.opt_out;
            return Some((encloser, opt_out));
        }
        None
    }
}

/// NSEC3 proof that `name` does not exist (RFC 5155 8.4): the closest
/// encloser proof, and no wildcard at the encloser.
pub(super) fn nsec3_nxdomain(zone: &Name, name: &Name, proof: &[Record]) -> Denial {
    let mut set = match nsec3_set(zone, proof) {
        Nsec3Params::Usable(set) => set,
        Nsec3Params::TooCostly => return Denial::Insecure,
        Nsec3Params::None => return Denial::Unproven,
    };
    let Some((encloser, opt_out)) = set.closest_encloser(zone, name) else {
        return Denial::Unproven;
    };
    let Some(wildcard) = wildcard_of(&encloser) else {
        return Denial::Unproven;
    };
    if set.covering(&wildcard).is_none() {
        return Denial::Unproven;
    }
    if opt_out {
        Denial::Insecure
    } else {
        Denial::Proven
    }
}

/// NSEC3 proof that `name` has no `qtype` records (RFC 5155 8.5 to 8.7):
/// an NSEC3 matching it without the type or a CNAME; for DS, also an opt-out
/// span covering it (an unsigned delegation, so insecure); or a wildcard
/// NODATA.
pub(super) fn nsec3_nodata(
    zone: &Name,
    name: &Name,
    qtype: RecordType,
    proof: &[Record],
) -> Denial {
    let mut set = match nsec3_set(zone, proof) {
        Nsec3Params::Usable(set) => set,
        Nsec3Params::TooCostly => return Denial::Insecure,
        Nsec3Params::None => return Denial::Unproven,
    };
    if let Some(matched) = set.matching(name) {
        let without =
            !matched.types.contains(&qtype) && !matched.types.contains(&RecordType::CNAME);
        let ds_ok = qtype != RecordType::DS || !matched.types.contains(&RecordType::SOA);
        return if without && ds_ok {
            Denial::Proven
        } else {
            Denial::Unproven
        };
    }
    let Some((encloser, opt_out)) = set.closest_encloser(zone, name) else {
        return Denial::Unproven;
    };
    if qtype == RecordType::DS && opt_out {
        return Denial::Insecure;
    }
    // A wildcard NODATA: the wildcard exists without the type.
    let Some(wildcard) = wildcard_of(&encloser) else {
        return Denial::Unproven;
    };
    match set.matching(&wildcard) {
        Some(matched)
            if !matched.types.contains(&qtype) && !matched.types.contains(&RecordType::CNAME) =>
        {
            Denial::Proven
        }
        _ => Denial::Unproven,
    }
}

/// NSEC3 proof for an answer synthesized from the wildcard below
/// `encloser`: the next closer name does not exist (RFC 5155 8.8).
pub(super) fn nsec3_wildcard(
    zone: &Name,
    name: &Name,
    encloser: &Name,
    proof: &[Record],
) -> Denial {
    let mut set = match nsec3_set(zone, proof) {
        Nsec3Params::Usable(set) => set,
        Nsec3Params::TooCostly => return Denial::Insecure,
        Nsec3Params::None => return Denial::Unproven,
    };
    let Some(next_closer) = name.suffix(encloser.label_count().saturating_add(1)) else {
        return Denial::Unproven;
    };
    match set.covering(&next_closer) {
        Some(covering) if covering.opt_out => Denial::Insecure,
        Some(_) => Denial::Proven,
        None => Denial::Unproven,
    }
}

/// The parent's proof that `zone` is an unsigned delegation, so everything
/// below it is insecure: the NSEC or NSEC3 at `zone` shows a delegation (NS)
/// without DS, from the parent's side (no SOA); or an NSEC3 opt-out span
/// covers it. A name that is no delegation (no NS) is not a zone, so a
/// signature claiming it as signer is bogus, not insecure.
pub(super) fn ds_denial(parent: &Name, zone: &Name, proof: &[Record]) -> Denial {
    let unsigned = |types: &[RecordType]| {
        types.contains(&RecordType::NS)
            && !types.contains(&RecordType::DS)
            && !types.contains(&RecordType::SOA)
    };
    if nsecs(proof).any(|(owner, nsec)| owner == zone && unsigned(&nsec.types)) {
        return Denial::Proven;
    }
    let mut set = match nsec3_set(parent, proof) {
        Nsec3Params::Usable(set) => set,
        Nsec3Params::TooCostly => return Denial::Insecure,
        Nsec3Params::None => return Denial::Unproven,
    };
    if let Some(matched) = set.matching(zone) {
        return if unsigned(&matched.types) {
            Denial::Proven
        } else {
            Denial::Unproven
        };
    }
    match set.closest_encloser(parent, zone) {
        Some((_, true)) => Denial::Insecure,
        _ => Denial::Unproven,
    }
}

/// Whether `cname` (unsigned) is what `dname` synthesizes (RFC 6672): its
/// owner below the DNAME's, and its target the owner with the DNAME's
/// owner replaced by the DNAME's target.
pub(super) fn synthesized(cname: &Record, dname: &Record) -> bool {
    let (Some(target), Some(dname_target)) = (cname.cname_target(), dname.dname_target()) else {
        return false;
    };
    let owner = cname.name();
    let below = dname.name();
    if owner == below || !owner.is_within(below) {
        return false;
    }
    let keep = owner.label_count().saturating_sub(below.label_count());
    let expected = Name::from_labels(owner.labels().take(keep).chain(dname_target.labels()));
    expected.is_ok_and(|expected| expected == target)
}

/// The RRSIGs, NSEC and NSEC3 records and DNAMEs of `records` owned by
/// names within `zone`: what validating an answer from `zone`'s servers may
/// use. At most [`MAX_EVIDENCE`].
pub(super) fn evidence<'a>(zone: &Name, records: impl Iterator<Item = &'a Record>) -> Vec<Record> {
    records
        .filter(|record| {
            matches!(
                record.record_type(),
                RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::DNAME
            ) && record.name().is_within(zone)
        })
        .take(MAX_EVIDENCE)
        .cloned()
        .collect()
}

/// The most DNSSEC records kept from one response.
pub(super) const MAX_EVIDENCE: usize = 128;

/// The most NSEC and NSEC3 records checked for one negative answer.
pub(super) const MAX_PROOFS: usize = 8;

/// `records` grouped into RRsets (same owner and type), in order of first
/// appearance.
pub(super) fn rrsets(records: &[Record]) -> Vec<Vec<Record>> {
    let mut sets: Vec<Vec<Record>> = Vec::new();
    for record in records {
        let set = sets.iter_mut().find(|set| {
            set.first().is_some_and(|first| {
                first.name() == record.name() && first.record_type() == record.record_type()
            })
        });
        match set {
            Some(set) => set.push(record.clone()),
            None => sets.push(vec![record.clone()]),
        }
    }
    sets
}

/// The RRSIGs of `sigs` that cover `owner`'s `rtype` records.
pub(super) fn covering<'a>(
    sigs: &'a [Record],
    owner: &'a Name,
    rtype: RecordType,
) -> impl Iterator<Item = (&'a Record, Rrsig)> + 'a {
    sigs.iter().filter_map(move |record| {
        let rrsig = record.rrsig()?;
        (record.name() == owner && rrsig.type_covered == rtype).then_some((record, rrsig))
    })
}

/// The zone that signed `owner`'s `rtype` records, as the first RRSIG
/// covering them says: a name `owner` is in, within `zone` (the zone whose
/// servers answered).
pub(super) fn signer(
    sigs: &[Record],
    owner: &Name,
    rtype: RecordType,
    zone: &Name,
) -> Option<Name> {
    covering(sigs, owner, rtype)
        .map(|(_, rrsig)| rrsig.signer)
        .find(|signer| owner.is_within(signer) && signer.is_within(zone))
}

/// The NSEC and NSEC3 records of `evidence` that `signer`'s `keys` sign, at
/// most [`MAX_PROOFS`] of them, and how long they may be kept.
pub(super) fn verified_proofs(
    evidence: &[Record],
    signer: &Name,
    keys: &[Record],
    now: u32,
    checks: &mut Checks,
) -> (Vec<Record>, u32) {
    let mut proofs = Vec::new();
    let mut ttl = u32::MAX;
    let candidates = evidence.iter().filter(|record| {
        matches!(record.record_type(), RecordType::NSEC | RecordType::NSEC3)
            && record.name().is_within(signer)
    });
    for record in candidates.take(MAX_PROOFS) {
        let rrset = std::slice::from_ref(record);
        if let Some(verified) = verify_rrset(rrset, evidence, signer, keys, now, checks) {
            ttl = ttl.min(verified.ttl).min(record.ttl());
            proofs.push(record.clone());
        }
    }
    (proofs, ttl)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use goethite_proto::dnssec::signing::{self, Key};

    use super::*;

    /// A name from its labels, so `*` may be one.
    fn name(text: &str) -> Name {
        Name::from_labels(
            text.split('.')
                .filter(|label| !label.is_empty())
                .map(str::as_bytes),
        )
        .unwrap()
    }

    const NOW: u32 = 1_800_000_000;

    fn sign(key: &Key, rrset: &[Record]) -> Record {
        key.sign(rrset, NOW - 86_400, NOW + 86_400)
    }

    #[test]
    fn rrsets_need_a_signature_by_a_zone_key_in_time() {
        let zone = name("example.");
        let key = Key::generate(&zone);
        let keys = vec![key.dnskey(3600)];
        let rrset = vec![Record::a(
            name("www.example."),
            300,
            Ipv4Addr::new(192, 0, 2, 1),
        )];
        let good = sign(&key, &rrset);
        let mut checks = Checks::new(MAX_CHECKS);
        let verified = verify_rrset(
            &rrset,
            std::slice::from_ref(&good),
            &zone,
            &keys,
            NOW,
            &mut checks,
        )
        .unwrap();
        assert_eq!(
            verified,
            Verified {
                ttl: 300,
                wildcard: None
            }
        );
        assert_eq!(checks.left, MAX_CHECKS - 1);

        // Expired a minute ago, within the slack for clocks: valid, but
        // not to be kept.
        let just_expired = key.sign(&rrset, NOW - 86_400, NOW - 60);
        let verified = verify_rrset(
            &rrset,
            std::slice::from_ref(&just_expired),
            &zone,
            &keys,
            NOW,
            &mut checks,
        )
        .unwrap();
        assert_eq!(verified.ttl, 0);

        // Expired, not yet valid, another signer, another key: no.
        for (inception, expiration) in [
            (NOW - 200_000, NOW - 100_000),
            (NOW + 100_000, NOW + 200_000),
        ] {
            let late = key.sign(&rrset, inception, expiration);
            assert!(verify_rrset(&rrset, &[late], &zone, &keys, NOW, &mut checks).is_none());
        }
        assert!(
            verify_rrset(
                &rrset,
                std::slice::from_ref(&good),
                &name("com."),
                &keys,
                NOW,
                &mut checks
            )
            .is_none()
        );
        let other = vec![Key::generate(&zone).dnskey(3600)];
        assert!(
            verify_rrset(
                &rrset,
                std::slice::from_ref(&good),
                &zone,
                &other,
                NOW,
                &mut checks
            )
            .is_none()
        );
        // Out of checks: no.
        let mut none = Checks::new(0);
        assert!(verify_rrset(&rrset, &[good], &zone, &keys, NOW, &mut none).is_none());
        assert!(none.ran_out() && !checks.ran_out());
    }

    #[test]
    fn wildcard_answers_say_so() {
        let zone = name("example.");
        let key = Key::generate(&zone);
        let wild = vec![Record::a(
            name("*.example."),
            300,
            Ipv4Addr::new(192, 0, 2, 7),
        )];
        let sig = sign(&key, &wild);
        // The answer for a.b.example, expanded from *.example.
        let mut answer = wild.clone();
        answer[0].set_name(name("a.b.example."));
        let mut sig_answer = sig.clone();
        sig_answer.set_name(name("a.b.example."));
        let verified = verify_rrset(
            &answer,
            &[sig_answer],
            &zone,
            &[key.dnskey(3600)],
            NOW,
            &mut Checks::new(8),
        )
        .unwrap();
        assert_eq!(verified.wildcard, Some(zone.clone()));
    }

    #[test]
    fn keys_chain_from_ds() {
        let zone = name("example.");
        let ksk = Key::generate(&zone);
        let zsk = Key::generate(&zone);
        let dnskeys_rrset = vec![ksk.dnskey(3600), zsk.dnskey(3600)];
        let mut dnskeys = dnskeys_rrset.clone();
        dnskeys.push(sign(&ksk, &dnskeys_rrset));
        let ds = vec![ksk.ds(86_400)];
        let (keys, ttl) = keys_from_ds(&zone, &ds, &dnskeys, NOW, &mut Checks::new(8)).unwrap();
        assert_eq!(keys.len(), 2, "every zone key, once the set is anchored");
        assert_eq!(ttl, 3600);
        // A DS for another key: not anchored.
        let stranger = vec![Key::generate(&zone).ds(86_400)];
        assert!(keys_from_ds(&zone, &stranger, &dnskeys, NOW, &mut Checks::new(8)).is_none());
        // Signed only by a key without a DS: not anchored.
        let mut zsk_signed = dnskeys_rrset.clone();
        zsk_signed.push(sign(&zsk, &dnskeys_rrset));
        assert!(keys_from_ds(&zone, &ds, &zsk_signed, NOW, &mut Checks::new(8)).is_none());
    }

    #[test]
    fn ds_digests_spend_from_the_budget() {
        let zone = name("example.");
        let ksk = Key::generate(&zone);
        let rrset = vec![ksk.dnskey(3600)];
        let mut dnskeys = rrset.clone();
        dnskeys.push(sign(&ksk, &rrset));
        let ds = vec![ksk.ds(86_400)];
        let mut checks = Checks::new(8);
        assert!(keys_from_ds(&zone, &ds, &dnskeys, NOW, &mut checks).is_some());
        assert_eq!(checks.left(), 6, "one digest and one signature check");
    }

    #[test]
    fn ds_digests_stop_at_the_budget() {
        let zone = name("example.");
        let ksk = Key::generate(&zone);
        let rrset = vec![ksk.dnskey(3600)];
        let mut dnskeys = rrset.clone();
        dnskeys.push(sign(&ksk, &rrset));
        let tag = ksk.dnskey(3600).dnskey().unwrap().key_tag;
        // A DS with the key's tag and algorithm, but a different digest:
        // only comparing digests tells it apart, which must spend a check.
        let forged = Record::ds_record(zone.clone(), 86_400, tag, 15, 2, vec![0; 32]);
        let ds = vec![forged, ksk.ds(86_400)];
        let mut checks = Checks::new(1);
        assert!(keys_from_ds(&zone, &ds, &dnskeys, NOW, &mut checks).is_none());
        assert!(checks.ran_out(), "the second digest needed a check");
    }

    fn nsec(owner: &str, next: &str, types: &[RecordType]) -> Record {
        signing::nsec(&name(owner), 300, &name(next), types)
    }

    #[test]
    fn nsec_proofs() {
        use RecordType as T;
        let proof = vec![
            nsec(
                "example.",
                "a.example.",
                &[T::SOA, T::NS, T::NSEC, T::RRSIG],
            ),
            nsec("a.example.", "d.example.", &[T::A, T::NSEC, T::RRSIG]),
            nsec("d.example.", "example.", &[T::NS, T::DS, T::NSEC, T::RRSIG]),
        ];
        // b.example: covered by a..d; its closest encloser is example, and
        // *.example is covered by example..a.
        assert!(nsec_nxdomain(&name("b.example."), &proof));
        assert!(!nsec_nxdomain(&name("a.example."), &proof), "exists");
        // z.example: covered by the last NSEC, wrapping round.
        assert!(nsec_nxdomain(&name("z.example."), &proof));
        // Below a delegation: the parent's NSEC there proves nothing.
        assert!(!nsec_nxdomain(&name("x.d.example."), &proof));
        // NODATA: a has A only.
        assert!(nsec_nodata(&name("a.example."), T::TXT, &proof));
        assert!(!nsec_nodata(&name("a.example."), T::A, &proof));
        // DS at the delegation d: present, so not denied; for a delegation
        // without DS it would be.
        assert!(!nsec_nodata(&name("d.example."), T::DS, &proof));
        let insecure = vec![nsec("d.example.", "example.", &[T::NS, T::NSEC, T::RRSIG])];
        assert!(nsec_nodata(&name("d.example."), T::DS, &insecure));
        // But that delegation NSEC proves nothing about other types there.
        assert!(!nsec_nodata(&name("d.example."), T::TXT, &insecure));
        assert!(nsec_wildcard(&name("c.example."), &proof));
        // An empty non-terminal: b.c.example has records, c.example none.
        let ent = vec![nsec(
            "a.example.",
            "b.c.example.",
            &[T::A, T::NSEC, T::RRSIG],
        )];
        assert!(nsec_nodata(&name("c.example."), T::A, &ent));
        assert!(!nsec_nodata(&name("bb.example."), T::A, &ent));
        // A wildcard NODATA: x.w.example comes from *.w.example, which has
        // TXT only.
        let wild = vec![
            nsec("w.example.", "*.w.example.", &[T::NSEC, T::RRSIG]),
            nsec("*.w.example.", "z.example.", &[T::TXT, T::NSEC, T::RRSIG]),
        ];
        assert!(nsec_nodata(&name("x.w.example."), T::A, &wild));
        assert!(!nsec_nodata(&name("x.w.example."), T::TXT, &wild));
    }

    #[test]
    fn nsec3_proofs() {
        use RecordType as T;
        let zone = name("example.");
        let hash = |n: &str| dnssec::nsec3_hash(&name(n), &[], 0).unwrap();
        // A chain over three existing names: example, a.example, *.w.example.
        let mut owners: Vec<(&str, Vec<u8>, Vec<RecordType>)> = vec![
            ("example.", hash("example."), vec![T::SOA, T::NS]),
            ("a.example.", hash("a.example."), vec![T::A]),
            ("w.example.", hash("w.example."), vec![]),
            ("*.w.example.", hash("*.w.example."), vec![T::TXT]),
        ];
        owners.sort_by(|x, y| x.1.cmp(&y.1));
        let proof: Vec<Record> = owners
            .iter()
            .enumerate()
            .map(|(i, (owner, _, types))| {
                let next = &owners[(i + 1) % owners.len()].1;
                signing::nsec3(&zone, &name(owner), 300, next, false, types)
            })
            .collect();
        assert_eq!(
            nsec3_nxdomain(&zone, &name("nope.example."), &proof),
            Denial::Proven
        );
        assert_eq!(
            nsec3_nxdomain(&zone, &name("a.example."), &proof),
            Denial::Unproven
        );
        assert_eq!(
            nsec3_nodata(&zone, &name("a.example."), T::TXT, &proof),
            Denial::Proven
        );
        assert_eq!(
            nsec3_nodata(&zone, &name("a.example."), T::A, &proof),
            Denial::Unproven
        );
        // Below w, the wildcard exists: no NXDOMAIN, but a wildcard NODATA
        // for a type it lacks.
        assert_eq!(
            nsec3_nxdomain(&zone, &name("x.w.example."), &proof),
            Denial::Unproven
        );
        assert_eq!(
            nsec3_nodata(&zone, &name("x.w.example."), T::A, &proof),
            Denial::Proven
        );
        assert_eq!(
            nsec3_wildcard(&zone, &name("x.w.example."), &name("w.example."), &proof),
            Denial::Proven
        );
    }

    #[test]
    fn only_real_delegations_are_unsigned() {
        use RecordType as T;
        let parent = name("example.");
        // shop is delegated without DS; www is an ordinary name.
        let proof = vec![
            nsec("shop.example.", "www.example.", &[T::NS, T::NSEC, T::RRSIG]),
            nsec("www.example.", "example.", &[T::A, T::NSEC, T::RRSIG]),
        ];
        assert_eq!(
            ds_denial(&parent, &name("shop.example."), &proof),
            Denial::Proven
        );
        // A signature claiming www as its signer cannot make www's data
        // insecure: www is no zone.
        assert_eq!(
            ds_denial(&parent, &name("www.example."), &proof),
            Denial::Unproven
        );
        // Nor can the child's own apex NSEC (it has SOA) stand in.
        let apex = vec![nsec(
            "shop.example.",
            "a.shop.example.",
            &[T::NS, T::SOA, T::NSEC, T::RRSIG],
        )];
        assert_eq!(
            ds_denial(&parent, &name("shop.example."), &apex),
            Denial::Unproven
        );
        // With NSEC3: the delegation matches, without DS.
        let hash = |n: &str| dnssec::nsec3_hash(&name(n), &[], 0).unwrap();
        let mut chain = [
            (name("example."), hash("example."), vec![T::SOA, T::NS]),
            (name("shop.example."), hash("shop.example."), vec![T::NS]),
        ];
        chain.sort_by(|x, y| x.1.cmp(&y.1));
        let nsec3s: Vec<Record> = chain
            .iter()
            .enumerate()
            .map(|(i, (owner, _, types))| {
                signing::nsec3(
                    &parent,
                    owner,
                    300,
                    &chain[(i + 1) % chain.len()].1,
                    false,
                    types,
                )
            })
            .collect();
        assert_eq!(
            ds_denial(&parent, &name("shop.example."), &nsec3s),
            Denial::Proven
        );
        assert_eq!(
            ds_denial(&parent, &name("example."), &nsec3s),
            Denial::Unproven
        );
    }

    #[test]
    fn dname_synthesis() {
        let dname = signing::dname(&name("old.example."), 300, &name("new.example."));
        let good = Record::cname(name("www.old.example."), 300, name("www.new.example."));
        let bad = Record::cname(name("www.old.example."), 300, name("evil.example."));
        assert!(synthesized(&good, &dname));
        assert!(!synthesized(&bad, &dname));
    }
}
