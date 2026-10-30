use std::sync::Arc;

use sqlx::PgPool;

use crate::{config::Config, storage::BlobStorage};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub storage: Arc<dyn BlobStorage>,
}
