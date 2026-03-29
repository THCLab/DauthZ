use serde::{Deserialize, Serialize};

use crate::challenge::Challenge;
use crate::challenge::ChallengeResponse;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum CeremonyState {
    #[default]
    AwaitingChallenge,
    AwaitingApproval {
        challenge: Challenge,
    },
    Responding {
        response: ChallengeResponse,
    },
    Completed,
    Failed(String),
}
