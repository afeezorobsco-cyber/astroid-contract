#![cfg(test)]
extern crate std;

use crate::{BatchCall, GovernanceChange, MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_shared::constants::{
    GOVERNANCE_GRACE_PERIOD, MAX_BATCH_CALLS, MAX_TIMELOCK_DELAY, MIN_TIMELOCK_DELAY,
    THRESHOLD_CHANGE_DELAY_LEDGERS,
};
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, AuthorizedFunction, Ledger};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, Env, IntoVal, Symbol,
    Val, Vec,
};

/// Minimal stateful contract used as a batch sub-call target: it stores values
/// keyed by id and exposes a couple of always-failing functions to exercise the
/// atomic rollback and error-mapping paths.
#[contract]
pub struct BatchHelper;

#[contracttype]
#[derive(Clone)]
enum HKey {
    Value(u64),
}

#[contractimpl]
impl BatchHelper {
    pub fn store(env: Env, key: u64, value: u64) {
        env.storage().instance().set(&HKey::Value(key), &value);
    }

    pub fn get(env: Env, key: u64) -> u64 {
        env.storage().instance().get(&HKey::Value(key)).unwrap_or(0)
    }

    /// Always fails with a contract error (atomic rollback + error propagation).
    pub fn fail(_env: Env) -> Result<(), Error> {
        Err(Error::InvalidInput)
    }

    /// Always panics (maps to [`Error::BatchCallFailed`]).
    pub fn boom(_env: Env) {
        panic!("boom");
    }
}

struct Harness {
    env: Env,
    client: MultiSigContractClient<'static>,
    signers: std::vec::Vec<Address>,
}

fn sw(a: &Address, w: u32) -> SignerWeight {
    SignerWeight {
        address: a.clone(),
        weight: w,
    }
}

fn setup(weights: &[u32], threshold: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let mut signers = std::vec::Vec::new();
    let mut sv = Vec::new(&env);
    for w in weights {
        let a = Address::generate(&env);
        sv.push_back(sw(&a, *w));
        signers.push(a);
    }
    client.initialize(&sv, &threshold);
    Harness {
        env,
        client,
        signers,
    }
}

fn advance(h: &Harness, seconds: u64) {
    let now = h.env.ledger().timestamp();
    h.env.ledger().set_timestamp(now + seconds);
}

fn payload(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4])
}

#[test]
fn initialize_state() {
    let h = setup(&[1, 1, 1], 2);
    assert_eq!(h.client.get_threshold(), 2);
    assert_eq!(h.client.get_signers().len(), 3);
    assert!(h.client.is_signer(&h.signers[0]));
    assert!(!h.client.is_locked());
}

#[test]
fn bad_threshold_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    // Total weight = 2, threshold 3 > total rejected.
    sv.push_back(sw(&Address::generate(&env), 1));
    sv.push_back(sw(&Address::generate(&env), 1));
    let res = client.try_initialize(&sv, &3);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn zero_weight_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    sv.push_back(sw(&Address::generate(&env), 0));
    sv.push_back(sw(&Address::generate(&env), 1));
    let res = client.try_initialize(&sv, &1);
    assert_eq!(res, Err(Ok(Error::InsufficientWeight)));
}

#[test]
fn duplicate_signer_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let a = Address::generate(&env);
    let mut sv = Vec::new(&env);
    sv.push_back(sw(&a, 1));
    sv.push_back(sw(&a, 1));
    let res = client.try_initialize(&sv, &1);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn weighted_approval_met_by_single_heavy_signer() {
    // Weights 5, 1, 1 with threshold 5: proposer (weight 5) alone executes.
    let h = setup(&[5, 1, 1], 5);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer's own weight (5) already meets threshold 5.
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn weighted_threshold_requires_combined_weight() {
    // Weights 2, 2, 1 with threshold 3.
    let h = setup(&[2, 2, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer contributes 2; one more signer (2) -> total 4 >= 3.
    let weight = h.client.approve(&h.signers[1], &id);
    assert_eq!(weight, 4);
    h.client.execute(&h.signers[2], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn execute_below_weight_threshold_fails() {
    // Weights 2, 2, 1 with threshold 3.
    let h = setup(&[2, 2, 1], 3);
    let _id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Only the weight-1 signer approves -> total 3 (proposer 2 + 1) < 3? 2+1=3 == threshold.
    // Use the lightest signer only so total stays below threshold.
    let id2 = h.client.propose(
        &h.signers[2],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // proposer weight 1; approve with weight-2 signer -> 1+2 = 3 meets threshold.
    // Instead approve with weight-2 signer only on a proposal from weight-1 signer gives 3.
    // To stay below, approve with no one: just proposer weight 1 < 3.
    let res = h.client.try_execute(&h.signers[0], &id2);
    assert_eq!(res, Err(Ok(Error::InsufficientWeight)));
}

#[test]
fn non_signer_cannot_propose_or_approve() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let res = h
        .client
        .try_propose(&stranger, &symbol_short!("payment"), &payload(&h.env), &0);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn double_approval_rejected() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer already auto-approved.
    let res = h.client.try_approve(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn time_lock_blocks_early_execution() {
    let h = setup(&[2, 2], 4);
    h.env.ledger().set_timestamp(1_000);
    let unlock = 5_000u64;
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &unlock,
    );
    h.client.approve(&h.signers[1], &id);
    // Threshold met (4), but time lock not reached.
    let res = h.client.try_execute(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));

    // Advance past the lock.
    h.env.ledger().set_timestamp(6_000);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn emergency_lock_blocks_actions() {
    let h = setup(&[1, 1], 2);
    h.client.set_emergency_lock(&h.signers[0], &true);
    assert!(h.client.is_locked());
    let res = h.client.try_propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));

    // Unlock and resume.
    h.client.set_emergency_lock(&h.signers[0], &false);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.approve(&h.signers[1], &id);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

// --- timelocked governance ---

#[test]
fn threshold_change_applies_only_after_the_timelock() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);

    // Parked, not applied: the live threshold is untouched.
    assert_eq!(h.client.get_threshold(), 2);
    let pending = h.client.get_pending_change(&id);
    assert_eq!(pending.proposer, h.signers[0]);
    assert_eq!(pending.change, GovernanceChange::Threshold(3));
    assert_eq!(pending.eta, pending.proposed_at + MIN_TIMELOCK_DELAY);
    assert_eq!(pending.expires_at, pending.eta + GOVERNANCE_GRACE_PERIOD);
    assert!(!pending.executed);
    assert!(!pending.cancelled);

    // One second short of the delay is still too early.
    advance(&h, MIN_TIMELOCK_DELAY - 1);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[1], &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(h.client.get_threshold(), 2);

    // Exactly at the eta the change goes through.
    advance(&h, 1);
    h.client.execute_threshold_change(&h.signers[1], &id);
    assert_eq!(h.client.get_threshold(), 3);
    assert!(h.client.get_pending_change(&id).executed);
}

#[test]
fn cancelled_change_never_executes() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);

    // Any signer may veto during the review window.
    h.client.cancel_threshold_change(&h.signers[1], &id);
    let pending = h.client.get_pending_change(&id);
    assert!(pending.cancelled);
    assert!(!pending.executed);

    advance(&h, MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.get_threshold(), 2);
}

#[test]
fn a_change_can_only_be_settled_once() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &id);

    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.client.try_cancel_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
}

#[test]
fn matured_change_expires_after_the_grace_period() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    advance(&h, MIN_TIMELOCK_DELAY + GOVERNANCE_GRACE_PERIOD);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(h.client.get_threshold(), 2);
}

#[test]
fn set_threshold_stores_pending_change() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Threshold is not yet changed.
    assert_eq!(h.client.get_threshold(), 2);
    let pending = h.client.get_pending_threshold();
    assert_eq!(pending.new_threshold, 3);
    assert_eq!(pending.effective_from, 100);
}

#[test]
fn set_threshold_same_value_fails() {
    let h = setup(&[1, 1, 1], 2);
    let res = h.client.try_set_threshold(&h.signers[0], &2);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn finalize_threshold_before_delay_fails() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Try to finalize immediately — not enough ledgers have passed.
    let res = h.client.try_finalize_threshold(&h.signers[0]);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    // Threshold unchanged.

    assert_eq!(h.client.get_threshold(), 2);
}

#[test]
fn cancellation_still_works_while_emergency_locked() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    h.client.set_emergency_lock(&h.signers[0], &true);

    // Proposing and executing are frozen, but a hostile change can still be
    // withdrawn — freezing the multisig must not trap a pending modification.
    assert_eq!(
        h.client.try_propose_threshold_change(&h.signers[0], &1),
        Err(Ok(Error::EmergencyLock))
    );
    advance(&h, MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::EmergencyLock))
    );
    h.client.cancel_threshold_change(&h.signers[1], &id);
    assert!(h.client.get_pending_change(&id).cancelled);
}

#[test]
fn non_signer_cannot_touch_governance() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let extra = Address::generate(&h.env);

    assert_eq!(
        h.client.try_propose_threshold_change(&stranger, &1),
        Err(Ok(Error::UnauthorizedModification))
    );
    assert_eq!(
        h.client.try_propose_signer_addition(&stranger, &extra, &1),
        Err(Ok(Error::UnauthorizedModification))
    );
    assert_eq!(
        h.client
            .try_propose_weight_change(&stranger, &h.signers[0], &5),
        Err(Ok(Error::UnauthorizedModification))
    );

    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    assert_eq!(
        h.client.try_cancel_threshold_change(&stranger, &id),
        Err(Ok(Error::UnauthorizedModification))
    );
    advance(&h, MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.client.try_execute_threshold_change(&stranger, &id),
        Err(Ok(Error::UnauthorizedModification))
    );
}

#[test]
fn threshold_bounds_enforced_at_proposal_time() {
    // Weights 1, 1, 1 total 3, threshold 2.
    let h = setup(&[1, 1, 1], 2);
    // A threshold above the total weight can never be met, so it is not parked.
    assert_eq!(
        h.client.try_propose_threshold_change(&h.signers[0], &4),
        Err(Ok(Error::InvalidThreshold))
    );
    // Zero is below MIN_THRESHOLD.
    assert_eq!(
        h.client.try_propose_threshold_change(&h.signers[0], &0),
        Err(Ok(Error::InvalidThreshold))
    );
    assert_eq!(h.client.get_change_count(), 0);

    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &id);
    assert_eq!(h.client.get_threshold(), 3);
}

#[test]
fn finalize_threshold_after_delay_succeeds() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Advance past the delay.
    h.env
        .ledger()
        .set_sequence_number(100 + THRESHOLD_CHANGE_DELAY_LEDGERS);
    h.client.finalize_threshold(&h.signers[0]);
    assert_eq!(h.client.get_threshold(), 3);
}

#[test]
fn execution_revalidates_against_live_state() {
    // Weights 2, 1, 1 (total 4) with threshold 2.
    let h = setup(&[2, 1, 1], 2);
    // Removing signer[0] leaves total weight 2, which satisfies the threshold
    // that is live right now, so the proposal is accepted.
    let removal = h
        .client
        .propose_signer_removal(&h.signers[1], &h.signers[0]);
    // Concurrently, the threshold is raised to 4.
    let raise = h.client.propose_threshold_change(&h.signers[1], &4);

    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[1], &raise);
    assert_eq!(h.client.get_threshold(), 4);

    // The removal is now unsafe — it would leave the multisig unusable — and is
    // rejected on the re-validation performed just before it is applied.
    assert_eq!(
        h.client
            .try_execute_threshold_change(&h.signers[1], &removal),
        Err(Ok(Error::InvalidThreshold))
    );
    assert!(h.client.is_signer(&h.signers[0]));
}

#[test]
fn finalize_threshold_no_pending_fails() {
    let h = setup(&[1, 1, 1], 2);
    let res = h.client.try_finalize_threshold(&h.signers[0]);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn set_threshold_overwrites_pending_change() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Change mind before finalization.
    h.env.ledger().set_sequence_number(150);
    h.client.set_threshold(&h.signers[0], &1);
    let pending = h.client.get_pending_threshold();
    assert_eq!(pending.new_threshold, 1);
    assert_eq!(pending.effective_from, 150);
    // Finalize the new pending change after the delay.
    h.env
        .ledger()
        .set_sequence_number(150 + THRESHOLD_CHANGE_DELAY_LEDGERS);
    h.client.finalize_threshold(&h.signers[0]);
    assert_eq!(h.client.get_threshold(), 1);
}

#[test]
fn non_signer_cannot_set_or_finalize_threshold() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_threshold(&stranger, &3),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_finalize_threshold(&stranger),
        Err(Ok(Error::NotASigner))
    );
}

#[test]
fn timelock_delay_is_itself_governed() {
    let h = setup(&[1, 1, 1], 2);
    assert_eq!(h.client.get_timelock_delay(), MIN_TIMELOCK_DELAY);

    // Out-of-range delays are refused up front.
    assert_eq!(
        h.client
            .try_propose_timelock_delay_change(&h.signers[0], &(MIN_TIMELOCK_DELAY - 1)),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        h.client
            .try_propose_timelock_delay_change(&h.signers[0], &(MAX_TIMELOCK_DELAY + 1)),
        Err(Ok(Error::InvalidInput))
    );

    // A change raised under the old delay keeps the eta it was given...
    let early = h.client.propose_threshold_change(&h.signers[0], &3);
    let longer = 3 * MIN_TIMELOCK_DELAY;
    let delay_change = h
        .client
        .propose_timelock_delay_change(&h.signers[0], &longer);

    advance(&h, MIN_TIMELOCK_DELAY);
    h.client
        .execute_threshold_change(&h.signers[0], &delay_change);
    assert_eq!(h.client.get_timelock_delay(), longer);

    // ...so it still executes on its original schedule.
    h.client.execute_threshold_change(&h.signers[0], &early);
    assert_eq!(h.client.get_threshold(), 3);

    // New proposals pick up the longer delay.
    let later = h.client.propose_threshold_change(&h.signers[0], &2);
    let pending = h.client.get_pending_change(&later);
    assert_eq!(pending.eta, pending.proposed_at + longer);
}

// --- timelocked signer-set changes ---

#[test]
fn add_and_remove_signer_with_weight() {
    let h = setup(&[1, 1, 1], 2);
    let new_signer = Address::generate(&h.env);
    h.client.add_signer(&h.signers[0], &new_signer, &3);
    assert!(h.client.is_signer(&new_signer));
    let stored = h.client.get_signers();
    assert!(stored
        .iter()
        .any(|s| s.address == new_signer && s.weight == 3));

    h.client.remove_signer(&h.signers[0], &new_signer);
    assert!(!h.client.is_signer(&new_signer));
}

#[test]
fn cannot_add_signer_with_zero_weight() {
    let h = setup(&[1, 1, 1], 2);
    let extra = Address::generate(&h.env);
    let res = h.client.try_add_signer(&h.signers[0], &extra, &0);
    assert_eq!(res, Err(Ok(Error::InvalidSignerWeight)));
}

#[test]
fn cannot_add_duplicate_signer() {
    let h = setup(&[1, 1, 1], 2);
    let res = h.client.try_add_signer(&h.signers[0], &h.signers[1], &1);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn update_signer_weight_and_reach_threshold() {
    // Weights 1, 1 with threshold 2.
    let h = setup(&[1, 1], 2);
    // Bump signer[0] to weight 5; must keep total >= threshold (ok).
    let id = h
        .client
        .propose_weight_change(&h.signers[1], &h.signers[0], &5);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[1], &id);
    let stored = h.client.get_signers();
    assert!(stored
        .iter()
        .any(|s| s.address == h.signers[0] && s.weight == 5));

    // A proposal from signer[0] now meets threshold alone.
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.execute(&h.signers[1], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn cannot_drop_total_weight_below_threshold() {
    // Weights 2, 1 with threshold 3.
    let h = setup(&[2, 1], 3);
    // Removing signer[0] (weight 2) leaves 1 < 3 -> rejected.
    let res = h.client.try_remove_signer(&h.signers[1], &h.signers[0]);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));

    // Lowering signer[0] weight to 1 would drop total to 2 < 3 -> rejected.
    let res = h
        .client
        .try_propose_weight_change(&h.signers[1], &h.signers[0], &1);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn set_threshold_bounds_enforced() {
    // Weights 1, 1, 1 total 3, threshold 2.
    let h = setup(&[1, 1, 1], 2);
    // Threshold larger than total weight is rejected.
    let res = h.client.try_set_threshold(&h.signers[0], &4);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
    // Valid update works (deferred via set_threshold + finalize_threshold).
    h.client.set_threshold(&h.signers[0], &3);
    h.env.ledger().set_sequence_number(17_280); // advance past THRESHOLD_CHANGE_DELAY_LEDGERS
    h.client.finalize_threshold(&h.signers[0]);
    assert_eq!(h.client.get_threshold(), 3);
}

#[test]
fn non_signer_cannot_change_config() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let extra = Address::generate(&h.env);
    assert_eq!(
        h.client.try_add_signer(&stranger, &extra, &1),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_set_threshold(&stranger, &1),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client
            .try_propose_weight_change(&stranger, &h.signers[0], &5),
        Err(Ok(Error::UnauthorizedModification))
    );
}

// --- batch execution ---

struct BatchHarness {
    env: Env,
    client: MultiSigContractClient<'static>,
    helper: Address,
    helper_client: BatchHelperClient<'static>,
    signers: std::vec::Vec<Address>,
}

/// Register the multisig plus a stateful helper contract and initialize with
/// `n` signers of weight 1 and the given threshold.
fn setup_batch(n: u32, threshold: u32) -> BatchHarness {
    let weights: std::vec::Vec<u32> = (0..n).map(|_| 1).collect();
    setup_batch_weighted(&weights, threshold)
}

/// As [`setup_batch`], but with an explicit voting weight per signer.
fn setup_batch_weighted(weights: &[u32], threshold: u32) -> BatchHarness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let helper = env.register_contract(None, BatchHelper);
    let helper_client = BatchHelperClient::new(&env, &helper);

    let mut signers = std::vec::Vec::new();
    let mut sv = Vec::new(&env);
    for w in weights {
        let a = Address::generate(&env);
        sv.push_back(sw(&a, *w));
        signers.push(a);
    }
    client.initialize(&sv, &threshold);
    BatchHarness {
        env,
        client,
        helper,
        helper_client,
        signers,
    }
}

/// Build a `Vec<Address>` from indices into the harness signer list.
fn approvers(env: &Env, signers: &[Address], idx: &[usize]) -> Vec<Address> {
    let mut v = Vec::new(env);
    for i in idx {
        v.push_back(signers[*i].clone());
    }
    v
}

fn store_call(env: &Env, helper: &Address, key: u64, value: u64) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("store"),
        args: vec![env, key.into_val(env), value.into_val(env)],
    }
}

fn fail_call(env: &Env, helper: &Address) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("fail"),
        args: Vec::new(env),
    }
}

fn boom_call(env: &Env, helper: &Address) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("boom"),
        args: Vec::new(env),
    }
}

#[test]
fn batch_executes_all_calls_under_single_threshold_check() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    // Caller (s0) plus one approver (s1) reach threshold 2.
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(h.helper_client.get(&1), 100);
    assert_eq!(h.helper_client.get(&2), 200);
    assert_eq!(h.client.get_last_batch_nonce(), 1);
}

#[test]
fn batch_below_threshold_rejected() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // Only the caller's signature (weight 1) < threshold 2.
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[]),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
    // Nothing was executed and the nonce was not consumed.
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_rejects_non_signer_approver() {
    let h = setup_batch(3, 2);
    let stranger = Address::generate(&h.env);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let app = vec![&h.env, h.signers[1].clone(), stranger];
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn batch_duplicate_approvers_do_not_stack_weight() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // The caller listed as approver too must still count once: 1 < threshold 2.
    let app = vec![&h.env, h.signers[0].clone()];
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn batch_nonce_replay_rejected() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let app = approvers(&h.env, &h.signers, &[1]);
    h.client.execute_batch(&h.signers[0], &1, &calls, &app);

    // Replaying the same nonce is rejected.
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));
    // A nonce below the initial counter is rejected too.
    let res = h.client.try_execute_batch(&h.signers[0], &0, &calls, &app);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));

    // Nonces are monotonic, not strictly sequential: gaps are allowed.
    let calls2 = vec![&h.env, store_call(&h.env, &h.helper, 2, 200)];
    h.client.execute_batch(&h.signers[0], &5, &calls2, &app);
    assert_eq!(h.client.get_last_batch_nonce(), 5);
}

#[test]
fn batch_rolls_back_all_calls_on_sub_call_failure() {
    let h = setup_batch(3, 2);
    // store(1) succeeds, then the middle call fails, then store(2) would run.
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        fail_call(&h.env, &h.helper),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    // The callee's own contract error is surfaced...
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // ...and no partial state was committed (atomicity).
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.helper_client.get(&2), 0);
    // The nonce was rolled back too, so the same batch can be retried.
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_sub_call_panic_maps_to_batch_call_failed() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        boom_call(&h.env, &h.helper),
    ];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::BatchCallFailed)));
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_signatures_cover_the_entire_payload() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    let app = approvers(&h.env, &h.signers, &[1]);
    h.client.execute_batch(&h.signers[0], &7, &calls, &app);

    let auths = h.env.auths();
    // The caller AND every approver authorized exactly the batch payload
    // `(nonce, calls)` — the same payload the contract re-derives internally.
    let expected: Vec<Val> = vec![&h.env, 7u64.into_val(&h.env), calls.to_val()];
    for signer in [&h.signers[0], &h.signers[1]] {
        assert!(
            auths.iter().any(|(addr, inv)| {
                addr == signer
                    && inv.function
                        == AuthorizedFunction::Contract((
                            h.client.address.clone(),
                            Symbol::new(&h.env, "execute_batch"),
                            expected.clone(),
                        ))
            }),
            "signer {signer:?} did not authorize the exact batch payload"
        );
    }
}

#[test]
fn batch_rejects_empty_calls() {
    let h = setup_batch(3, 2);
    let calls = Vec::new(&h.env);
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn batch_rejects_too_many_calls() {
    let h = setup_batch(3, 2);
    let mut calls = Vec::new(&h.env);
    for i in 0..MAX_BATCH_CALLS + 1 {
        calls.push_back(store_call(&h.env, &h.helper, i as u64, i as u64));
    }
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn batch_requires_signer_caller() {
    let h = setup_batch(3, 2);
    let stranger = Address::generate(&h.env);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let res =
        h.client
            .try_execute_batch(&stranger, &1, &calls, &approvers(&h.env, &h.signers, &[1]));
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn batch_blocked_by_emergency_lock() {
    let h = setup_batch(3, 2);
    h.client.set_emergency_lock(&h.signers[0], &true);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));
}

#[test]
fn batch_execution_uses_signer_weights() {
    // A single heavy signer carries the batch on its own.
    let h = setup_batch_weighted(&[5, 1, 1], 5);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[]),
    );
    assert_eq!(h.helper_client.get(&1), 100);

    // The two light signers together fall short of the same threshold.
    let res = h.client.try_execute_batch(
        &h.signers[1],
        &2,
        &calls,
        &approvers(&h.env, &h.signers, &[2]),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

// --- standalone threshold verification ---

#[test]
fn verify_threshold_accumulates_weight_of_distinct_signers() {
    let h = setup(&[3, 2, 1], 5);
    let weight = h.client.verify_threshold(
        &h.signers[0],
        &approvers(&h.env, &h.signers, &[1]),
        &payload(&h.env),
    );
    assert_eq!(weight, 5);
}

#[test]
fn verify_threshold_below_threshold_is_refused() {
    let h = setup(&[3, 2, 1], 5);
    let res = h.client.try_verify_threshold(
        &h.signers[1],
        &approvers(&h.env, &h.signers, &[2]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn verify_threshold_counts_a_repeated_signatory_once() {
    let h = setup(&[3, 2, 1], 5);
    // s0 listed as its own signatory must not stack its weight to 6.
    let res = h.client.try_verify_threshold(
        &h.signers[0],
        &approvers(&h.env, &h.signers, &[0]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn verify_threshold_rejects_unregistered_signatories() {
    let h = setup(&[3, 2, 1], 5);
    let stranger = Address::generate(&h.env);
    let signatories = vec![&h.env, stranger];
    let res = h
        .client
        .try_verify_threshold(&h.signers[0], &signatories, &payload(&h.env));
    assert_eq!(res, Err(Ok(Error::NotASigner)));

    let stranger = Address::generate(&h.env);
    let res = h.client.try_verify_threshold(
        &stranger,
        &approvers(&h.env, &h.signers, &[1]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn verify_threshold_is_blocked_by_the_emergency_lock() {
    let h = setup(&[3, 2, 1], 5);
    h.client.set_emergency_lock(&h.signers[0], &true);
    let res = h.client.try_verify_threshold(
        &h.signers[0],
        &approvers(&h.env, &h.signers, &[1]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));
}

#[test]
fn weight_views_report_the_configured_weights() {
    let h = setup(&[3, 2, 1], 5);
    assert_eq!(h.client.get_signer_weight(&h.signers[0]), 3);
    assert_eq!(h.client.get_signer_weight(&h.signers[2]), 1);
    assert_eq!(h.client.get_signer_weight(&Address::generate(&h.env)), 0);
    assert_eq!(h.client.get_total_weight(), 6);
}
