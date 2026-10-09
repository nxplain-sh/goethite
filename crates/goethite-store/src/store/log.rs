//! The cluster's log, beside the configuration it builds: the entries the
//! cluster agreed on (or is agreeing on), and values of the cluster's own,
//! such as this node's vote. The store keeps them as bytes and leaves their
//! meaning to the cluster (`goethite-cluster`).
//!
//! Nothing here takes the writer lock: a change made on this node holds it
//! while the change goes through the log.

use std::ops::RangeBounds;
use std::sync::PoisonError;

use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::{META, Store, StoreError};

/// The log: entries by index.
pub(super) const LOG: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("cluster_log");

/// The prefix of the cluster's values in the `meta` table.
const PREFIX: &str = "cluster_";

/// Just past every key with [`PREFIX`]: `` ` `` follows `_`.
const PREFIX_END: &str = "cluster`";

impl Store {
    /// Appends `entries`, as (index, bytes), to the log, replacing any at
    /// the same indexes. They are on disk when this returns.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn log_append(&self, entries: &[(u64, Vec<u8>)]) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(LOG)?;
            for (index, bytes) in entries {
                table.insert(*index, bytes.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The entries with indexes in `range`, in order.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn log_entries(
        &self,
        range: impl RangeBounds<u64>,
    ) -> Result<Vec<(u64, Vec<u8>)>, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(LOG)?;
        let mut entries = Vec::new();
        for row in table.range(range)? {
            let (index, bytes) = row?;
            entries.push((index.value(), bytes.value().to_vec()));
        }
        Ok(entries)
    }

    /// The last entry, if there is one.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn log_last(&self) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(LOG)?;
        Ok(table
            .last()?
            .map(|(index, bytes)| (index.value(), bytes.value().to_vec())))
    }

    /// Removes the entries from `index` on.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn log_truncate(&self, index: u64) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        tx.open_table(LOG)?.retain_in(index.., |_, _| false)?;
        tx.commit()?;
        Ok(())
    }

    /// Removes the entries up to and including `index`, and sets the
    /// cluster's value `key` to `value` in the same transaction: where the
    /// log now starts.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn log_purge(&self, index: u64, key: &str, value: &str) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        tx.open_table(LOG)?.retain_in(..=index, |_, _| false)?;
        tx.open_table(META)?
            .insert(format!("{PREFIX}{key}").as_str(), value)?;
        tx.commit()?;
        Ok(())
    }

    /// A value of the cluster's own, such as this node's vote.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn cluster_value(&self, key: &str) -> Result<Option<String>, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(META)?;
        Ok(table
            .get(format!("{PREFIX}{key}").as_str())?
            .map(|value| value.value().to_owned()))
    }

    /// Sets a value of the cluster's own, or removes it with `None`. It is
    /// on disk when this returns.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn set_cluster_value(&self, key: &str, value: Option<&str>) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(META)?;
            let key = format!("{PREFIX}{key}");
            match value {
                Some(value) => {
                    table.insert(key.as_str(), value)?;
                }
                None => {
                    table.remove(key.as_str())?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Forgets the cluster: its log and all of its values, including its
    /// note of what the configuration includes. The configuration stays.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn leave_cluster(&self) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        tx.open_table(LOG)?.retain(|_, _| false)?;
        tx.open_table(META)?
            .retain_in(PREFIX..PREFIX_END, |_, _| false)?;
        tx.commit()?;
        self.current
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .applied = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_entries_round_trip() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.log_last().unwrap(), None);
        store
            .log_append(&[
                (1, b"one".to_vec()),
                (2, b"two".to_vec()),
                (3, b"three".to_vec()),
            ])
            .unwrap();
        assert_eq!(store.log_last().unwrap(), Some((3, b"three".to_vec())));
        assert_eq!(
            store.log_entries(2..).unwrap(),
            vec![(2, b"two".to_vec()), (3, b"three".to_vec())]
        );
        store.log_truncate(3).unwrap();
        assert_eq!(store.log_last().unwrap(), Some((2, b"two".to_vec())));
        store.log_purge(1, "purged", "1").unwrap();
        assert_eq!(store.log_entries(..).unwrap(), vec![(2, b"two".to_vec())]);
        assert_eq!(store.cluster_value("purged").unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn leaving_forgets_the_cluster_and_keeps_the_configuration() {
        let store = Store::open_in_memory().unwrap();
        store.set_cluster_value("vote", Some("v")).unwrap();
        store.set_cluster_value("id", Some("7")).unwrap();
        store.set_meta("imported_filter", "abc").unwrap();
        store.log_append(&[(1, b"one".to_vec())]).unwrap();
        let version = store.version();
        store.leave_cluster().unwrap();
        assert_eq!(store.cluster_value("vote").unwrap(), None);
        assert_eq!(store.cluster_value("id").unwrap(), None);
        assert_eq!(store.log_last().unwrap(), None);
        assert_eq!(
            store.meta("imported_filter").unwrap().as_deref(),
            Some("abc")
        );
        assert_eq!(store.version(), version);
        store.set_cluster_value("vote", None).unwrap();
    }
}
