use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DauthzPayload {
    pub i: String,
    pub o: String,
    pub s: String,
}
