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
            (total_count + page_size - 1) / page_size
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
