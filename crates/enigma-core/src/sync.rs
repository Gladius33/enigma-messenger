pub struct SyncEngine;

impl SyncEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn tick(&self) {}
}

impl Default for SyncEngine {
    fn default() -> Self {
        Self::new()
    }
}
