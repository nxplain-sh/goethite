//! How big the recommended lists say they are, for the Lists page: lists
//! change size daily, so goethite reads the number from each list's header
//! rather than keeping one.
//!
//! Only when someone asks, this node reads the first
//! [`recommended::HEADER_LEN`] bytes of each recommended list (a range
//! request, cut off there if the server sends more), a few at a time, over
//! HTTPS through goethite's own resolver. The result is kept for [`KEEP`],
//! and one refresh runs at a time.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwapOption;
use goethite_api::recommended::{self, RecommendedSizes, StatedSize};
use goethite_resolver::Resolver;
use jiff::Timestamp;
use rustls::ClientConfig;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::debug;

use crate::download::Downloader;

/// How long the sizes are kept.
pub(crate) const KEEP: Duration = Duration::from_hours(24);

/// How long reading one list's header may take.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Headers read at once.
const PARALLEL: usize = 6;

struct Cached {
    at: Instant,
    sizes: RecommendedSizes,
}

/// The recommended lists' stated sizes, read on demand.
pub(crate) struct ListSizes {
    downloader: Arc<Downloader>,
    cached: ArcSwapOption<Cached>,
    refresh: Semaphore,
}

impl ListSizes {
    /// Reads headers resolving with `resolver` and checking certificates
    /// with `tls`.
    pub(crate) fn new(resolver: Arc<Resolver>, tls: Arc<ClientConfig>) -> Self {
        Self {
            downloader: Arc::new(Downloader::new(resolver, tls, recommended::HEADER_LEN)),
            cached: ArcSwapOption::empty(),
            refresh: Semaphore::new(1),
        }
    }

    fn fresh(&self) -> Option<RecommendedSizes> {
        self.cached
            .load_full()
            .filter(|cached| cached.at.elapsed() < KEEP)
            .map(|cached| cached.sizes.clone())
    }

    /// The sizes, read again once they are older than [`KEEP`]. A list whose
    /// header cannot be read, or states no size, is left out.
    ///
    /// # Errors
    ///
    /// Only if the refresh cannot start.
    pub(crate) async fn sizes(&self) -> Result<RecommendedSizes> {
        if let Some(sizes) = self.fresh() {
            return Ok(sizes);
        }
        let _refreshing = self.refresh.acquire().await?;
        if let Some(sizes) = self.fresh() {
            return Ok(sizes);
        }
        let slots = Arc::new(Semaphore::new(PARALLEL));
        let mut reads = JoinSet::new();
        for list in recommended::LISTS {
            let downloader = Arc::clone(&self.downloader);
            let slots = Arc::clone(&slots);
            reads.spawn(async move {
                let _slot = slots.acquire_owned().await.ok()?;
                let read = timeout(
                    HEADER_TIMEOUT,
                    downloader.fetch_start(list.url, recommended::HEADER_LEN),
                )
                .await;
                match read {
                    Ok(Ok(head)) => recommended::stated_size(&head).map(|entries| StatedSize {
                        id: list.id.to_owned(),
                        entries,
                    }),
                    Ok(Err(err)) => {
                        debug!(list = list.id, "cannot read the list's header: {err:#}");
                        None
                    }
                    Err(_) => {
                        debug!(list = list.id, "reading the list's header timed out");
                        None
                    }
                }
            });
        }
        let mut lists = Vec::new();
        while let Some(read) = reads.join_next().await {
            lists.extend(read.ok().flatten());
        }
        lists.sort_by(|a, b| a.id.cmp(&b.id));
        let sizes = RecommendedSizes {
            fetched_at: Timestamp::now(),
            lists,
        };
        self.cached.store(Some(Arc::new(Cached {
            at: Instant::now(),
            sizes: sizes.clone(),
        })));
        Ok(sizes)
    }
}
