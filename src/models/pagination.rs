use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Standard Page-Based Query Parameters
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
pub struct PageParams {
    /// Page number (1-indexed, default: 1)
    #[param(default = 1, minimum = 1)]
    pub page: Option<u64>,

    /// Items per page (default: 20, max: 100)
    #[param(default = 20, minimum = 1, maximum = 100)]
    pub page_size: Option<u64>,
}

impl PageParams {
    pub fn page(&self) -> u64 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn page_size(&self) -> u64 {
        self.page_size.unwrap_or(20).clamp(1, 100)
    }

    pub fn offset(&self) -> u64 {
        (self.page() - 1) * self.page_size()
    }

    pub fn limit(&self) -> u64 {
        self.page_size()
    }
}

/// Standard Page-Based Metadata for Envelope
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PageMeta {
    pub page: u64,
    pub page_size: u64,
    pub total_pages: u64,
    pub total_count: u64,
    pub has_next: bool,
    pub has_previous: bool,
}

impl PageMeta {
    pub fn new(page: u64, page_size: u64, total_count: u64) -> Self {
        let total_pages = if total_count == 0 {
            0
        } else {
            total_count.div_ceil(page_size)
        };

        Self {
            page,
            page_size,
            total_pages,
            total_count,
            has_next: page < total_pages,
            has_previous: page > 1 && total_pages > 0,
        }
    }
}

/// Standard Cursor-Based Query Parameters
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
pub struct CursorParams {
    /// Limit number of items (default: 20, max: 100)
    #[param(default = 20, minimum = 1, maximum = 100)]
    pub limit: Option<u64>,

    /// Opaque cursor token for next page
    pub cursor: Option<String>,
}

impl CursorParams {
    pub fn limit(&self) -> u64 {
        self.limit.unwrap_or(20).clamp(1, 100)
    }
}

/// Standard Cursor-Based Metadata for Envelope
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CursorMeta {
    pub limit: u64,
    pub has_next: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_cursor: Option<String>,
}

/// Opaque keyset cursor for append-only feeds.
///
/// `OFFSET` pagination re-scans everything it skips, so it degrades on exactly
/// the high-volume tables (audit logs, notifications) that need paging most.
/// Encoding the last row's sort key instead keeps every page a constant-cost
/// index seek, and it does not skip or duplicate rows when new ones arrive
/// mid-traversal.
#[derive(Debug, Clone, Copy)]
pub struct Cursor {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub id: uuid::Uuid,
}

impl Cursor {
    pub fn encode(&self) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(format!(
            "{}|{}",
            self.created_at.timestamp_micros(),
            self.id
        ))
    }

    pub fn decode(raw: &str) -> Option<Self> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let decoded = URL_SAFE_NO_PAD.decode(raw).ok()?;
        let text = String::from_utf8(decoded).ok()?;
        let (micros, id) = text.split_once('|')?;
        Some(Self {
            created_at: chrono::DateTime::from_timestamp_micros(micros.parse().ok()?)?,
            id: id.parse().ok()?,
        })
    }
}

impl CursorMeta {
    /// Build metadata from a page that was fetched with one extra row, which is
    /// how "is there a next page" is answered without a second query.
    pub fn from_page(limit: u64, has_next: bool, last: Option<Cursor>) -> Self {
        Self {
            limit,
            has_next,
            next_cursor: if has_next {
                last.map(|c| c.encode())
            } else {
                None
            },
            previous_cursor: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips() {
        let cursor = Cursor {
            created_at: chrono::Utc::now(),
            id: uuid::Uuid::now_v7(),
        };
        let decoded = Cursor::decode(&cursor.encode()).expect("cursor should decode");
        assert_eq!(decoded.id, cursor.id);
        assert_eq!(
            decoded.created_at.timestamp_micros(),
            cursor.created_at.timestamp_micros()
        );
    }

    #[test]
    fn malformed_cursors_are_rejected_rather_than_panicking() {
        for bad in ["", "!!!!", "Zm9v", "bm90LWEtY3Vyc29y"] {
            assert!(
                Cursor::decode(bad).is_none(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn page_meta_computes_bounds() {
        let m = PageMeta::new(2, 20, 45);
        assert_eq!(m.total_pages, 3);
        assert!(m.has_next && m.has_previous);
        let empty = PageMeta::new(1, 20, 0);
        assert_eq!(empty.total_pages, 0);
        assert!(!empty.has_next && !empty.has_previous);
    }
}
