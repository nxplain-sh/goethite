//! Blocked services: well-known services, such as TikTok or YouTube, that a
//! group can block whole.
//!
//! The catalog's rules are compiled into [`goethite_filter::Filter`]s of
//! up to 64 services each, one source per service, so a match still says
//! which service it was. A group holds a [`ServiceMask`] of the services it
//! blocks: a fixed-size bitset, so checking a query allocates nothing.

use std::sync::Arc;

use goethite_filter::{Filter, FilterBuilder, FilterError, Match, Rule, Source, Sources, Verdict};
use goethite_proto::Name;

/// The most services a catalog holds.
pub const MAX_SERVICES: usize = 1_024;

/// The longest service ID.
pub const MAX_SERVICE_ID_LEN: usize = 64;

/// Whether `text` is a valid service ID: 1 to [`MAX_SERVICE_ID_LEN`]
/// lowercase ASCII letters, digits, underscores and hyphens, such as
/// `tiktok` or `amazon_streaming`.
pub fn is_service_id(text: &str) -> bool {
    (1..=MAX_SERVICE_ID_LEN).contains(&text.len())
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

/// Services per compiled filter: a filter tells 64 sources apart.
const PER_CHUNK: usize = 64;

/// Words in a [`ServiceMask`].
const WORDS: usize = MAX_SERVICES / PER_CHUNK;

/// A set of services, by their index in a [`ServiceFilter`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ServiceMask([u64; WORDS]);

impl ServiceMask {
    /// No service.
    pub const NONE: Self = Self([0; WORDS]);

    /// This set with service `index` added; out-of-range indexes are
    /// ignored.
    #[must_use]
    pub fn with(mut self, index: usize) -> Self {
        if let Some(word) = self.0.get_mut(index / PER_CHUNK) {
            *word |= 1_u64 << (index % PER_CHUNK);
        }
        self
    }

    /// Both sets.
    #[must_use]
    pub fn union(mut self, other: Self) -> Self {
        for (word, other) in self.0.iter_mut().zip(other.0) {
            *word |= other;
        }
        self
    }

    /// Whether it holds no service.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    /// Whether it holds service `index`.
    pub fn contains(&self, index: usize) -> bool {
        self.0
            .get(index / PER_CHUNK)
            .is_some_and(|word| word & (1_u64 << (index % PER_CHUNK)) != 0)
    }
}

/// A service and its rules, ready to compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRules {
    /// The service's ID, such as `tiktok`.
    pub id: Arc<str>,
    /// Its rules.
    pub rules: Vec<Rule>,
}

/// The catalog's services, compiled.
pub struct ServiceFilter {
    chunks: Vec<Filter>,
    ids: Vec<Arc<str>>,
    /// `service:<id>`, for the query log.
    sources: Vec<Arc<str>>,
}

impl std::fmt::Debug for ServiceFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceFilter")
            .field("services", &self.ids.len())
            .finish_non_exhaustive()
    }
}

/// Why a catalog cannot be compiled.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServiceError {
    /// More than [`MAX_SERVICES`] services.
    #[error("more than {MAX_SERVICES} services")]
    TooMany,
    /// The filter could not be built.
    #[error(transparent)]
    Filter(#[from] FilterError),
}

impl ServiceFilter {
    /// Compiles `services`; a service's index is its position.
    ///
    /// # Errors
    ///
    /// [`ServiceError::TooMany`] past [`MAX_SERVICES`], or an error building
    /// a filter.
    pub fn build(services: &[ServiceRules]) -> Result<Self, ServiceError> {
        if services.len() > MAX_SERVICES {
            return Err(ServiceError::TooMany);
        }
        let mut chunks = Vec::with_capacity(services.len().div_ceil(PER_CHUNK));
        for chunk in services.chunks(PER_CHUNK) {
            let mut builder = FilterBuilder::new();
            for (index, service) in chunk.iter().enumerate() {
                let Some(source) = Source::new(index) else {
                    continue;
                };
                for rule in &service.rules {
                    builder.add_rule(source, rule);
                }
            }
            chunks.push(builder.build()?);
        }
        Ok(Self {
            chunks,
            ids: services
                .iter()
                .map(|service| Arc::clone(&service.id))
                .collect(),
            sources: services
                .iter()
                .map(|service| Arc::from(format!("service:{}", service.id)))
                .collect(),
        })
    }

    /// No services.
    pub fn empty() -> Self {
        Self {
            chunks: Vec::new(),
            ids: Vec::new(),
            sources: Vec::new(),
        }
    }

    /// The index of service `id`, if the catalog has it.
    pub fn index(&self, id: &str) -> Option<usize> {
        self.ids.iter().position(|known| &**known == id)
    }

    /// The ID of the service at `index`.
    pub fn id(&self, index: usize) -> Option<&Arc<str>> {
        self.ids.get(index)
    }

    /// `service:<id>` for the service at `index`: what the query log
    /// records as the source of a block.
    pub fn source_id(&self, index: usize) -> Option<&Arc<str>> {
        self.sources.get(index)
    }

    /// How many services it has.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether it has no services.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// The first service in `mask` whose rules block `name`, with the rule
    /// that did.
    pub fn check(&self, name: &Name, mask: &ServiceMask) -> Option<(usize, Match)> {
        for (chunk, (filter, word)) in self.chunks.iter().zip(mask.0).enumerate() {
            if word == 0 {
                continue;
            }
            if let Verdict::Blocked(matched) = filter.check(name, Sources::from_bits(word)) {
                let index = chunk
                    .checked_mul(PER_CHUNK)?
                    .checked_add(matched.source.index())?;
                return Some((index, matched));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use goethite_filter::{LineKind, parse_line};

    use super::*;

    fn service(id: &str, lines: &[&str]) -> ServiceRules {
        let mut rules = Vec::new();
        for line in lines {
            assert!(matches!(
                parse_line(line, |rule| rules.push(rule)),
                LineKind::Rules(_)
            ));
        }
        ServiceRules {
            id: id.into(),
            rules,
        }
    }

    #[test]
    fn says_which_service_blocked_a_name() {
        // 70 services: two filters.
        let mut services: Vec<ServiceRules> = (0..68)
            .map(|i| service(&format!("filler{i}"), &[&format!("||filler{i}.example^")]))
            .collect();
        services.push(service("tiktok", &["||tiktok.com^", "|exact.tiktokv.com^"]));
        services.push(service("youtube", &["||youtube.com^"]));
        let filter = ServiceFilter::build(&services).unwrap();
        assert_eq!(filter.len(), 70);
        let tiktok = filter.index("tiktok").unwrap();
        let youtube = filter.index("youtube").unwrap();
        assert_eq!(tiktok, 68);
        let mask = ServiceMask::NONE.with(tiktok);
        let name = |text: &str| text.parse::<Name>().unwrap();

        let (index, matched) = filter.check(&name("www.tiktok.com"), &mask).unwrap();
        assert_eq!(filter.id(index).map(|id| &**id), Some("tiktok"));
        assert_eq!(
            matched.rule_text(&name("www.tiktok.com"), goethite_filter::Action::Block),
            "||tiktok.com^"
        );
        assert!(filter.check(&name("exact.tiktokv.com"), &mask).is_some());
        assert!(
            filter
                .check(&name("sub.exact.tiktokv.com"), &mask)
                .is_none(),
            "exact rule"
        );
        assert!(
            filter.check(&name("youtube.com"), &mask).is_none(),
            "not in the mask"
        );
        let both = mask.union(ServiceMask::NONE.with(youtube));
        assert_eq!(
            filter.check(&name("m.youtube.com"), &both).map(|(i, _)| i),
            Some(youtube)
        );
        assert!(filter.check(&name("filler3.example"), &both).is_none());
        assert!(
            filter
                .check(&name("tiktok.com"), &ServiceMask::NONE)
                .is_none()
        );
    }

    #[test]
    fn service_ids() {
        for good in ["tiktok", "amazon_streaming", "9gag", "battle-net"] {
            assert!(is_service_id(good), "{good}");
        }
        for bad in ["", "TikTok", "tik tok", "tik.tok", &"a".repeat(65)] {
            assert!(!is_service_id(bad), "{bad}");
        }
    }

    #[test]
    fn masks() {
        let mask = ServiceMask::NONE.with(0).with(64).with(1_023).with(5_000);
        assert!(mask.contains(0) && mask.contains(64) && mask.contains(1_023));
        assert!(!mask.contains(1) && !mask.contains(5_000));
        assert!(!mask.is_empty());
        assert!(ServiceMask::NONE.is_empty());
        let too_many: Vec<ServiceRules> = (0..=MAX_SERVICES)
            .map(|i| service(&format!("s{i}"), &["||a.example^"]))
            .collect();
        assert!(matches!(
            ServiceFilter::build(&too_many),
            Err(ServiceError::TooMany)
        ));
    }
}
