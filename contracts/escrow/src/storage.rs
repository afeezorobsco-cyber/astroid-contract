use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use astroid_shared::types::AssetAmount;
use soroban_sdk::{contracttype, Address, BytesN, Env, String, Vec};

/// Release type for time-locked escrow schedules.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseType {
    /// Standard escrow without automated schedule.
    None = 0,
    /// 100% unlocked at cliff_time / end_time (bullet release).
    Cliff = 1,
    /// Linearly unlocked between start_time and end_time (with optional cliff).
    Linear = 2,
}

/// Release schedule configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSchedule {
    pub release_type: ReleaseType,
    pub start_time: u64,
    pub cliff_time: u64,
    pub end_time: u64,
}

impl ReleaseSchedule {
    pub fn none() -> Self {
        Self {
            release_type: ReleaseType::None,
            start_time: 0,
            cliff_time: 0,
            end_time: 0,
        }
    }
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EscrowState {
    Created = 0,
    Funded = 1,
    Released = 2,
    Refunded = 3,
    Expired = 4,
    Closed = 5,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow {
    pub sender: Address,
    pub recipient: Address,
    pub arbiter: Address,
    pub assets: Vec<AssetAmount>,
    pub state: EscrowState,
    pub deadline: u64,
    /// Extra time after `deadline` during which the arbiter may still release
    /// and before the sender may reclaim. 0 means no grace beyond the deadline.
    pub grace_period: u64,
    /// How long the sender may reclaim the funds once refunds open at
    /// `deadline + grace_period`. `0` leaves the window open forever; a bounded
    /// window lets settlement logic treat an un-refunded, timed-out escrow as
    /// final.
    pub refund_window: u64,
    pub funded_amount: i128,
    pub memo: String,
    pub schedule: ReleaseSchedule,
    pub released_amount: i128,
    pub override_signers: Vec<BytesN<32>>,
    pub override_threshold: u32,
    pub override_nonce: u64,
    /// Pending beneficiary replacement address (None = no proposal active).
    pub proposed_beneficiary: Option<Address>,
    /// Ledger sequence at which the beneficiary proposal was created.
    pub proposed_at_seq: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Count,
    Escrow(u64),
    Milestones(u64),
}

pub fn get_count(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::Count).unwrap_or(0)
}

pub fn increment_count(env: &Env) -> Result<u64, Error> {
    let count = get_count(env);
    let next = checked_add(count as i128, 1)? as u64;
    env.storage().instance().set(&DataKey::Count, &next);
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    Ok(next)
}

pub fn load_escrow(env: &Env, id: u64) -> Result<Escrow, Error> {
    env.storage()
        .persistent()
        .get(&DataKey::Escrow(id))
        .ok_or(Error::NotFound)
}

pub fn store_escrow(env: &Env, id: u64, escrow: &Escrow) {
    env.storage().persistent().set(&DataKey::Escrow(id), escrow);
    bump_escrow(env, id);
}

pub fn bump_escrow(env: &Env, id: u64) {
    env.storage().persistent().extend_ttl(
        &DataKey::Escrow(id),
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}
