#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid MultiSig Contract
//!
//! Prevents unilateral spending by requiring an approval **weight** threshold
//! before an action executes (PRD Doc 7 §MultiSig). Each signer is assigned a
//! positive voting weight and the contract tracks the accumulated weight of
//! approvals against a configurable `threshold` (expressed in weight units,
//! not raw signer count). This lets organizations give different administrative
//! keys or partner entities proportionally larger influence.
//!
//! The contract owns a dynamic weighted signer set and a threshold, and manages
//! internal proposals through an approve → execute flow with an optional
//! per-proposal time lock and a global emergency lock.
//!
//! [`MultiSigContract::execute_batch`] additionally supports bundling multiple
//! discrete contract calls into one transaction: each contributing signer's
//! signature is verified (by the Soroban host) over the exact batch payload
//! `(nonce, calls)`, the aggregate signature weight must meet the threshold, and
//! the nonce makes batches replay-proof. Execution is atomic — if any sub-call
//! fails the whole batch reverts with [`Error::BatchCallFailed`] or the callee's
//! error.
//!
//! [`MultiSigContract::verify_threshold`] exposes that same signature check on
//! its own, without executing anything: it verifies a set of signatures over an
//! exact payload, accumulates the weight of the distinct registered signers
//! behind them, and returns the total or [`Error::ThresholdNotMet`]. Duplicated
//! signatories are counted once, so a single key can never reach the threshold
//! alone however often it is listed.
//!
//! ## Timelocked governance
//!
//! Changing who can sign, how much a signer's vote is worth, or the threshold
//! itself is the most security-sensitive operation the contract exposes: a
//! single compromised key that could apply such a change instantly would own
//! the multisig. Every one of those modifications therefore goes through a
//! two-step, timelocked flow instead of taking effect immediately:
//!
//! ```text
//! propose_* → (>= timelock delay elapses) → execute_threshold_change
//!                   ↘ cancel_threshold_change (any signer, any time)
//! ```
//!
//! The pending change is stored with the `eta` computed at proposal time, so
//! shortening the delay later can never accelerate an in-flight change. A
//! matured change stays executable for [`GOVERNANCE_GRACE_PERIOD`] and then
//! expires, so stale proposals cannot lie dormant and fire much later. The
//! delay itself is governed the same way (`propose_timelock_delay_change`) and
//! is clamped to `[MIN_TIMELOCK_DELAY, MAX_TIMELOCK_DELAY]`, so no single
//! signer can shrink the review window to nothing.
//!
//! Events: `signer/added`, `signer/removed`, `signer/weight`,
//! `threshold/changed`, `timelock/changed`, `govchange/proposed`,
//! `govchange/executed`, `govchange/cancelled`, `proposal/approved`,
//! `proposal/executed`, `batch/executed`, `emergency/lock`.
//!
//! Execution below the weight threshold is rejected with
//! [`Error::InsufficientWeight`]; premature governance execution with
//! [`Error::TimelockNotExpired`]; governance calls from a non-signer with
//! [`Error::UnauthorizedModification`].

use astroid_shared::constants::{
    GOVERNANCE_GRACE_PERIOD, INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_BATCH_CALLS,
    MAX_SIGNERS, MAX_TIMELOCK_DELAY, MIN_THRESHOLD, MIN_TIMELOCK_DELAY, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD, THRESHOLD_CHANGE_DELAY_LEDGERS,
};
use astroid_shared::errors::Error;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::validation::require_time_reached;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, Env, IntoVal, Symbol,
    Val, Vec,
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Config: current weighted signer set (instance).
    Signers,
    /// Config: current approval weight threshold (instance).
    Threshold,
    /// State: global emergency lock flag (instance).
    EmergencyLock,
    /// State: monotonic proposal id counter (instance).
    ProposalCount,
    /// State: proposal record by id (persistent).
    Proposal(u64),
    /// Relationship: whether a signer approved a proposal (persistent).
    Approval(u64, Address),
    /// Threshold value attached to a threshold-update proposal (persistent).
    ProposalThreshold(u64),
    /// State: last used batch nonce (instance); batches must use a greater one.
    LastBatchNonce,
    /// Config: timelock delay applied to governance changes (instance, seconds).
    TimelockDelay,
    /// State: monotonic governance-change id counter (instance).
    ChangeCount,
    /// State: pending governance change by id (persistent).
    Change(u64),
    /// Pending threshold change awaiting finalization.
    PendingThreshold,
}

/// A registered signer and its positive voting weight.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerWeight {
    pub address: Address,
    pub weight: u32,
}

/// A pending threshold change that must wait a delay before finalization.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingThresholdChange {
    pub new_threshold: u32,
    /// Ledger sequence when the change was submitted.
    pub effective_from: u32,
}

/// Internal multisig proposal. `action`/`payload` describe the intended change
/// or call; the multisig only records weighted approvals and marks it executed
/// once the accumulated weight meets the threshold. Actual value movement is
/// delegated to the calling context (e.g. the Treasury) which checks
/// `is_executed`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsProposal {
    pub proposer: Address,
    /// A short action tag, e.g. `payment`, `config`.
    pub action: Symbol,
    /// Opaque payload (e.g. serialized transfer intent / hash).
    pub payload: Bytes,
    /// Accumulated approval weight (sum of approver weights).
    pub approval_weight: u32,
    pub executed: bool,
    /// Earliest timestamp at which execution is allowed (time lock; 0 = none).
    pub unlock_at: u64,
}

/// A governance modification awaiting the timelock. Each variant carries the
/// exact post-state it will apply, so what was proposed is what executes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernanceChange {
    /// Set the approval weight threshold to the given value.
    Threshold(u32),
    /// Set an existing signer's voting weight.
    SignerWeight(Address, u32),
    /// Admit a new signer with the given positive weight.
    AddSigner(Address, u32),
    /// Drop an existing signer.
    RemoveSigner(Address),
    /// Change the timelock delay applied to future governance proposals.
    TimelockDelay(u64),
}

/// A proposed governance change parked behind the timelock.
///
/// `eta` is fixed at proposal time and is the earliest timestamp at which
/// [`MultiSigContract::execute_threshold_change`] will apply the change;
/// `expires_at` bounds how long the matured change stays executable.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingChange {
    /// Signer that raised the change.
    pub proposer: Address,
    /// The modification that will be applied on execution.
    pub change: GovernanceChange,
    /// Ledger timestamp at which the change was proposed.
    pub proposed_at: u64,
    /// Earliest timestamp at which execution is permitted.
    pub eta: u64,
    /// Timestamp at (and after) which the change can no longer be executed.
    pub expires_at: u64,
    pub executed: bool,
    pub cancelled: bool,
}

/// A single discrete contract call inside a batch. `args` are raw Soroban
/// values, so any contract function can be targeted.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchCall {
    /// Contract to invoke.
    pub contract: Address,
    /// Function to invoke on the target contract.
    pub func: Symbol,
    /// Arguments passed to the target function.
    pub args: Vec<Val>,
}

#[contract]
pub struct MultiSigContract;

#[contractimpl]
impl MultiSigContract {
    // --- registry-gated upgrades ---

    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    pub fn set_upgrade_authority(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        admin: soroban_sdk::Address,
        registry: soroban_sdk::Address,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    pub fn get_upgrade_authority(
        env: soroban_sdk::Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for [`ModuleKind::Multisig`] in the registry. Any
    /// other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Multisig,
            wasm_hash,
        )
    }
    /// Initialize with an initial weighted signer set and a weight threshold.
    /// `threshold` must be within `[MIN_THRESHOLD, total_weight]` and the signer
    /// set within `MAX_SIGNERS`, with all weights positive and addresses unique.
    pub fn initialize(env: Env, signers: Vec<SignerWeight>, threshold: u32) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }
        let n = signers.len();
        if n == 0 || n > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }
        for s in signers.iter() {
            if s.weight == 0 {
                return Err(Error::InsufficientWeight);
            }
        }
        let total = Self::total_weight(&signers)?;
        Self::validate_threshold(threshold, total)?;
        Self::assert_unique(&signers)?;

        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        env.storage()
            .instance()
            .set(&DataKey::EmergencyLock, &false);
        env.storage().instance().set(&DataKey::ProposalCount, &0u64);
        env.storage()
            .instance()
            .set(&DataKey::LastBatchNonce, &0u64);
        env.storage().instance().set(&DataKey::ChangeCount, &0u64);
        env.storage()
            .instance()
            .set(&DataKey::TimelockDelay, &MIN_TIMELOCK_DELAY);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Add a signer. Signer-gated. Rejects duplicates, zero weights, and
    /// over-capacity signer sets.
    pub fn add_signer(
        env: Env,
        caller: Address,
        signer: Address,
        weight: u32,
    ) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        if weight == 0 {
            return Err(Error::InvalidSignerWeight);
        }
        let mut signers = Self::signers(&env)?;
        if signers.iter().any(|s| s.address == signer) {
            return Err(Error::AlreadyExists);
        }
        if signers.len() >= MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        signers.push_back(SignerWeight {
            address: signer.clone(),
            weight,
        });
        env.storage().instance().set(&DataKey::Signers, &signers);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("signer"), symbol_short!("added")),
            (signer, weight),
        );
        Ok(())
    }

    /// Remove a signer. Signer-gated. Refuses to drop below the threshold or to
    /// empty the set, so the multisig can never become unusable.
    pub fn remove_signer(env: Env, caller: Address, signer: Address) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let mut signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        let idx = Self::index_of(&signers, &signer)?;
        let remaining_total = Self::total_weight(&signers)? - signers.get(idx).unwrap().weight;
        if remaining_total < threshold {
            return Err(Error::InvalidThreshold);
        }
        signers.remove(idx);
        env.storage().instance().set(&DataKey::Signers, &signers);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("signer"), symbol_short!("removed")), signer);
        Ok(())
    }

    /// Propose a pending threshold change. Signer-gated. Must stay within
    /// `[MIN_THRESHOLD, signers.len()]`. The change is stored but not applied
    /// until [`finalize_threshold`] is called after the grace period.
    pub fn set_threshold(env: Env, caller: Address, threshold: u32) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let signers = Self::signers(&env)?;
        Self::validate_threshold(threshold, Self::total_weight(&signers)?)?;

        let current = Self::threshold(&env)?;
        if current == threshold {
            return Err(Error::InvalidThreshold);
        }

        let pending = PendingThresholdChange {
            new_threshold: threshold,
            effective_from: env.ledger().sequence(),
        };
        env.storage()
            .instance()
            .set(&DataKey::PendingThreshold, &pending);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("threshold"), symbol_short!("pending")),
            (threshold, env.ledger().sequence()),
        );
        Ok(())
    }

    /// Finalize a pending threshold change. The change only takes effect after
    /// at least [`THRESHOLD_CHANGE_DELAY_LEDGERS`] ledgers have passed since
    /// the change was submitted via [`set_threshold`].
    pub fn finalize_threshold(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;

        let pending: PendingThresholdChange = env
            .storage()
            .instance()
            .get(&DataKey::PendingThreshold)
            .ok_or(Error::NotFound)?;

        let current_sequence = env.ledger().sequence();
        let elapsed = current_sequence
            .checked_sub(pending.effective_from)
            .ok_or(Error::TimelockNotExpired)?;
        if elapsed < THRESHOLD_CHANGE_DELAY_LEDGERS {
            return Err(Error::TimelockNotExpired);
        }

        env.storage()
            .instance()
            .set(&DataKey::Threshold, &pending.new_threshold);
        env.storage().instance().remove(&DataKey::PendingThreshold);
        env.events().publish(
            (symbol_short!("threshold"), symbol_short!("changed")),
            pending.new_threshold,
        );
        Self::bump_instance(&env);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Timelocked governance: signer set, voting weights and the threshold.
    //
    // None of these take effect immediately. `propose_*` parks the change with
    // an `eta`; `execute_threshold_change` applies it once the delay elapsed;
    // `cancel_threshold_change` lets any signer veto it during the window.
    // -----------------------------------------------------------------------

    /// Propose raising or lowering the approval weight threshold.
    ///
    /// Signer-gated. The value is validated against the current total signer
    /// weight up front so an unsatisfiable threshold is never parked, and
    /// re-validated on execution in case the signer set moved meanwhile.
    /// Returns the id used to execute or cancel the change.
    pub fn propose_threshold_change(
        env: Env,
        caller: Address,
        new_threshold: u32,
    ) -> Result<u64, Error> {
        Self::propose_change(&env, &caller, GovernanceChange::Threshold(new_threshold))
    }

    /// Propose changing an existing signer's voting weight. Signer-gated. The
    /// resulting total weight must stay at or above the threshold.
    pub fn propose_weight_change(
        env: Env,
        caller: Address,
        signer: Address,
        new_weight: u32,
    ) -> Result<u64, Error> {
        Self::propose_change(
            &env,
            &caller,
            GovernanceChange::SignerWeight(signer, new_weight),
        )
    }

    /// Propose admitting a new signer with a positive weight. Signer-gated.
    /// Rejects duplicates, zero weights and over-capacity signer sets.
    pub fn propose_signer_addition(
        env: Env,
        caller: Address,
        signer: Address,
        weight: u32,
    ) -> Result<u64, Error> {
        Self::propose_change(&env, &caller, GovernanceChange::AddSigner(signer, weight))
    }

    /// Propose removing a signer. Signer-gated. Refuses to drop the remaining
    /// total weight below the threshold, so the multisig can never be bricked.
    pub fn propose_signer_removal(
        env: Env,
        caller: Address,
        signer: Address,
    ) -> Result<u64, Error> {
        Self::propose_change(&env, &caller, GovernanceChange::RemoveSigner(signer))
    }

    /// Propose a new timelock delay for *future* governance proposals.
    ///
    /// Signer-gated and itself timelocked, so the review window cannot be
    /// shortened without first surviving the current one. The value is clamped
    /// to `[MIN_TIMELOCK_DELAY, MAX_TIMELOCK_DELAY]`.
    pub fn propose_timelock_delay_change(
        env: Env,
        caller: Address,
        new_delay: u64,
    ) -> Result<u64, Error> {
        Self::propose_change(&env, &caller, GovernanceChange::TimelockDelay(new_delay))
    }

    /// Execute a pending governance change once its timelock has elapsed.
    ///
    /// Signer-gated. Fails with [`Error::TimelockNotExpired`] before `eta`,
    /// [`Error::ProposalExpired`] once the grace period lapsed, and
    /// [`Error::InvalidProposalState`] if the change was already executed or
    /// cancelled. The change is re-validated against live state immediately
    /// before it is applied.
    pub fn execute_threshold_change(
        env: Env,
        caller: Address,
        proposal_id: u64,
    ) -> Result<(), Error> {
        Self::require_not_locked(&env)?;
        Self::require_governor(&env, &caller)?;
        let mut pending = Self::load_change(&env, proposal_id)?;
        Self::require_change_open(&pending)?;

        let now = env.ledger().timestamp();
        if now < pending.eta {
            return Err(Error::TimelockNotExpired);
        }
        if now >= pending.expires_at {
            return Err(Error::ProposalExpired);
        }

        // The signer set may have moved since the proposal was raised; only
        // apply a change that is still valid against live state.
        Self::validate_change(&env, &pending.change)?;
        Self::apply_change(&env, &pending.change)?;

        pending.executed = true;
        let kind = Self::change_kind(&pending.change);
        env.storage()
            .persistent()
            .set(&DataKey::Change(proposal_id), &pending);
        Self::bump_change(&env, proposal_id);
        env.events().publish(
            (symbol_short!("govchange"), symbol_short!("executed")),
            (proposal_id, caller, kind),
        );
        Ok(())
    }

    /// Veto a pending governance change. Any signer may cancel, which is the
    /// point of the timelock: honest key holders get a window to stop a
    /// malicious modification raised by a compromised key.
    ///
    /// Deliberately callable while the emergency lock is engaged — freezing the
    /// multisig must not also freeze the ability to withdraw a hostile change.
    pub fn cancel_threshold_change(
        env: Env,
        caller: Address,
        proposal_id: u64,
    ) -> Result<(), Error> {
        Self::require_governor(&env, &caller)?;
        let mut pending = Self::load_change(&env, proposal_id)?;
        Self::require_change_open(&pending)?;
        pending.cancelled = true;
        let kind = Self::change_kind(&pending.change);
        env.storage()
            .persistent()
            .set(&DataKey::Change(proposal_id), &pending);
        Self::bump_change(&env, proposal_id);
        env.events().publish(
            (symbol_short!("govchange"), symbol_short!("cancelled")),
            (proposal_id, caller, kind),
        );
        Ok(())
    }

    /// Propose a threshold update through the collective approval flow. Only a
    /// signer may propose. The `new_threshold` is validated against the current
    /// signer set and persisted alongside the proposal so that
    /// [`execute_threshold_update`] can apply it once quorum is reached.
    pub fn propose_threshold_update(
        env: Env,
        proposer: Address,
        new_threshold: u32,
        unlock_at: u64,
    ) -> Result<u64, Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &proposer)?;
        let signers = Self::signers(&env)?;
        let total = Self::total_weight(&signers)?;
        if new_threshold == 0 || new_threshold > total {
            return Err(Error::InvalidThreshold);
        }

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let proposer_weight = Self::weight_of(&env, &proposer)?;
        let proposal = MsProposal {
            proposer: proposer.clone(),
            action: symbol_short!("threshupd"),
            payload: Bytes::new(&env),
            approval_weight: proposer_weight,
            executed: false,
            unlock_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage()
            .persistent()
            .set(&DataKey::Approval(id, proposer.clone()), &true);
        env.storage()
            .persistent()
            .set(&DataKey::ProposalThreshold(id), &new_threshold);
        Self::bump_proposal(&env, id);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCount, &count);
        Self::bump_instance(&env);

        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("created")),
            (id, proposer),
        );
        Ok(id)
    }

    /// Execute an approved threshold-update proposal. Any signer may call once
    /// the proposal has accumulated sufficient approval weight. The stored
    /// `new_threshold` is validated, the threshold is persisted, and a
    /// `ThresholdUpdated` event is emitted.
    pub fn execute_threshold_update(
        env: Env,
        caller: Address,
        proposal_id: u64,
    ) -> Result<(), Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &caller)?;
        let mut proposal = Self::load_proposal(&env, proposal_id)?;
        if proposal.executed {
            return Err(Error::InvalidProposalState);
        }
        let threshold = Self::threshold(&env)?;
        if proposal.approval_weight < threshold {
            return Err(Error::InsufficientWeight);
        }
        if proposal.unlock_at != 0 {
            require_time_reached(&env, proposal.unlock_at)?;
        }

        let new_threshold: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProposalThreshold(proposal_id))
            .ok_or(Error::NotFound)?;
        let signers = Self::signers(&env)?;
        Self::validate_threshold(new_threshold, Self::total_weight(&signers)?)?;

        let old_threshold = threshold;
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &new_threshold);

        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        Self::bump_proposal(&env, proposal_id);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("threshold"), symbol_short!("updated")),
            (old_threshold, new_threshold),
        );
        Ok(())
    }

    /// Toggle the global emergency lock (signer-gated). While locked, proposals
    /// cannot be created, approved or executed.
    pub fn set_emergency_lock(env: Env, caller: Address, locked: bool) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        env.storage()
            .instance()
            .set(&DataKey::EmergencyLock, &locked);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("emergency"), symbol_short!("lock")), locked);
        Ok(())
    }

    /// Create a proposal. Only a signer may propose. `unlock_at` sets an optional
    /// time lock (0 = immediately executable once threshold met). The proposer's
    /// weight is counted automatically.
    pub fn propose(
        env: Env,
        proposer: Address,
        action: Symbol,
        payload: Bytes,
        unlock_at: u64,
    ) -> Result<u64, Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &proposer)?;

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let proposer_weight = Self::weight_of(&env, &proposer)?;
        let proposal = MsProposal {
            proposer: proposer.clone(),
            action,
            payload,
            approval_weight: proposer_weight,
            executed: false,
            unlock_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage()
            .persistent()
            .set(&DataKey::Approval(id, proposer.clone()), &true);
        Self::bump_proposal(&env, id);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCount, &count);
        Self::bump_instance(&env);

        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("created")),
            (id, proposer),
        );
        Ok(id)
    }

    /// Approve a proposal. Only signers may approve, once each. Their weight is
    /// added to the accumulated total. Emits `ProposalApproved` with the running
    /// weight.
    pub fn approve(env: Env, caller: Address, proposal_id: u64) -> Result<u32, Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &caller)?;
        let mut proposal = Self::load_proposal(&env, proposal_id)?;
        if proposal.executed {
            return Err(Error::InvalidProposalState);
        }
        let akey = DataKey::Approval(proposal_id, caller.clone());
        if env.storage().persistent().get(&akey).unwrap_or(false) {
            return Err(Error::AlreadySigned);
        }
        let weight = Self::weight_of(&env, &caller)?;
        env.storage().persistent().set(&akey, &true);
        proposal.approval_weight =
            checked_add(proposal.approval_weight as i128, weight as i128)? as u32;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        Self::bump_proposal(&env, proposal_id);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("approved")),
            (proposal_id, caller, proposal.approval_weight),
        );
        Ok(proposal.approval_weight)
    }

    /// Execute a proposal once the accumulated approval weight meets the
    /// threshold and any time lock has elapsed. Marks it executed and emits
    /// `ProposalExecuted`. Rejects with [`Error::InsufficientWeight`] when the
    /// accumulated weight is below the threshold.
    pub fn execute(env: Env, caller: Address, proposal_id: u64) -> Result<(), Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &caller)?;
        let mut proposal = Self::load_proposal(&env, proposal_id)?;
        if proposal.executed {
            return Err(Error::InvalidProposalState);
        }
        let threshold = Self::threshold(&env)?;
        if proposal.approval_weight < threshold {
            return Err(Error::InsufficientWeight);
        }
        if proposal.unlock_at != 0 {
            require_time_reached(&env, proposal.unlock_at)?;
        }
        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        Self::bump_proposal(&env, proposal_id);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("executed")),
            proposal_id,
        );
        Ok(())
    }

    /// Execute a batch of discrete contract calls under a single threshold
    /// verification. Bundling several calls into one transaction reduces fees
    /// and makes multi-step administrative operations atomic.
    ///
    /// - `caller` must be a current signer. Its signature is verified against
    ///   the batch payload itself and counts toward the threshold (mirroring
    ///   how a proposer auto-approves in the proposal flow), so every
    ///   contributing signer signs the exact same payload.
    /// - `nonce` must be strictly greater than the last used batch nonce, which
    ///   makes batches replay-proof; the nonce is part of the signed payload.
    /// - `calls` must be non-empty and within [`MAX_BATCH_CALLS`].
    /// - `approvers` lists any additional signers backing the batch. Every
    ///   listed approver must be a current signer and must authorize the exact
    ///   payload `(nonce, calls)`; the host cryptographically verifies each
    ///   signature and enforces replay prevention via
    ///   [`Address::require_auth_for_args`]. Duplicate entries (including the
    ///   caller) only count once. Each distinct signer contributes its own
    ///   voting weight, so the accumulated weight — caller plus approvers —
    ///   must meet the threshold.
    ///
    /// Execution is atomic: each call runs inside a Soroban error-handling
    /// boundary ([`Env::try_invoke_contract`]); if any sub-call fails the whole
    /// batch reverts (including the nonce), so no partial state is committed.
    /// A failing sub-call surfaces its own contract error when known, otherwise
    /// [`Error::BatchCallFailed`].
    pub fn execute_batch(
        env: Env,
        caller: Address,
        nonce: u64,
        calls: Vec<BatchCall>,
        approvers: Vec<Address>,
    ) -> Result<(), Error> {
        Self::require_not_locked(&env)?;
        let signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        if !signers.iter().any(|s| s.address == caller) {
            return Err(Error::NotASigner);
        }

        if calls.is_empty() || calls.len() > MAX_BATCH_CALLS {
            return Err(Error::InvalidInput);
        }
        // A list longer than the maximum signer set can only hold duplicates or
        // non-signers; reject it up front (gas safety).
        if approvers.len() > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }

        // Replay protection: batch nonces must be strictly increasing.
        let last_nonce: u64 = env
            .storage()
            .instance()
            .get(&DataKey::LastBatchNonce)
            .unwrap_or(0);
        if nonce <= last_nonce {
            return Err(Error::InvalidNonce);
        }

        // Aggregate signature verification over the entire batch payload: the
        // caller plus every distinct approver must be a signer and must have
        // authorized `(nonce, calls)`. Each distinct signer contributes its own
        // voting weight.
        let payload = Self::batch_payload(&env, nonce, &calls);
        let weight = Self::accumulate_weight(&env, &signers, &caller, &approvers, &payload)?;
        if weight < threshold {
            return Err(Error::ThresholdNotMet);
        }

        env.storage()
            .instance()
            .set(&DataKey::LastBatchNonce, &nonce);

        // Execute every call atomically; any failure reverts the whole batch.
        for call in calls.iter() {
            Self::execute_call(&env, &call)?;
        }

        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("batch"), symbol_short!("executed")),
            (nonce, caller, calls.len()),
        );
        Ok(())
    }

    /// Verify that a collection of signatures over `payload` carries at least
    /// the configured approval weight threshold.
    ///
    /// `caller` and every entry in `signatories` must be a registered signer and
    /// must have authorized this exact payload — the Soroban host performs the
    /// cryptographic signature verification via
    /// [`Address::require_auth_for_args`], and binding the check to `payload`
    /// means a signature collected for one operation can never be replayed
    /// against another. Repeated signatories count once, so a single key can
    /// never stack its own weight to reach the threshold alone.
    ///
    /// This exposes the same check `execute_batch` performs internally, so a
    /// caller can verify a signature set against the threshold without asking
    /// the multisig to execute anything.
    ///
    /// Returns the accumulated weight on success, [`Error::NotASigner`] when an
    /// unregistered address is presented, and [`Error::ThresholdNotMet`] when
    /// the verified weight falls short.
    pub fn verify_threshold(
        env: Env,
        caller: Address,
        signatories: Vec<Address>,
        payload: Bytes,
    ) -> Result<u32, Error> {
        Self::require_not_locked(&env)?;
        // A list longer than the maximum signer set can only hold duplicates or
        // non-signers; reject it up front (gas safety).
        if signatories.len() > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }
        let signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        let args = vec![&env, payload.to_val()];
        let weight = Self::accumulate_weight(&env, &signers, &caller, &signatories, &args)?;
        if weight < threshold {
            return Err(Error::ThresholdNotMet);
        }
        Ok(weight)
    }

    // --- views ---

    /// Voting weight of `who`, or 0 when it is not a registered signer.
    pub fn get_signer_weight(env: Env, who: Address) -> u32 {
        Self::weight_of(&env, &who).unwrap_or(0)
    }

    /// Aggregate voting weight of the whole signer set.
    pub fn get_total_weight(env: Env) -> Result<u32, Error> {
        Self::total_weight(&Self::signers(&env)?)
    }

    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<MsProposal, Error> {
        Self::load_proposal(&env, proposal_id)
    }

    /// Last used batch nonce. The next `execute_batch` call must pass a strictly
    /// greater nonce.
    pub fn get_last_batch_nonce(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::LastBatchNonce)
            .unwrap_or(0)
    }

    pub fn get_signers(env: Env) -> Vec<SignerWeight> {
        Self::signers(&env).unwrap_or_else(|_| Vec::new(&env))
    }

    pub fn get_threshold(env: Env) -> Result<u32, Error> {
        Self::threshold(&env)
    }

    pub fn get_pending_threshold(env: Env) -> Result<PendingThresholdChange, Error> {
        env.storage()
            .instance()
            .get(&DataKey::PendingThreshold)
            .ok_or(Error::NotFound)
    }

    pub fn is_signer(env: Env, who: Address) -> bool {
        Self::signers(&env)
            .map(|s| s.iter().any(|sw| sw.address == who))
            .unwrap_or(false)
    }

    pub fn is_locked(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::EmergencyLock)
            .unwrap_or(false)
    }

    /// Read a pending (or already executed/cancelled) governance change.
    pub fn get_pending_change(env: Env, proposal_id: u64) -> Result<PendingChange, Error> {
        Self::load_change(&env, proposal_id)
    }

    /// The timelock delay currently applied to newly proposed governance
    /// changes, in seconds.
    pub fn get_timelock_delay(env: Env) -> u64 {
        Self::timelock_delay(&env)
    }

    /// Number of governance changes ever proposed; ids run `1..=count`.
    pub fn get_change_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::ChangeCount)
            .unwrap_or(0)
    }

    // --- internal helpers ---

    fn signers(env: &Env) -> Result<Vec<SignerWeight>, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)
    }

    fn total_weight(signers: &Vec<SignerWeight>) -> Result<u32, Error> {
        let mut total: i128 = 0;
        let len = signers.len();
        let mut i = 0;
        while i < len {
            let w = signers.get(i).unwrap().weight;
            total = checked_add(total, w as i128)?;
            i += 1;
        }
        Self::to_weight(total)
    }

    /// Narrow an accumulated `i128` weight back to `u32`, refusing to truncate.
    fn to_weight(total: i128) -> Result<u32, Error> {
        if total > u32::MAX as i128 {
            return Err(Error::Overflow);
        }
        Ok(total as u32)
    }

    fn weight_of(env: &Env, who: &Address) -> Result<u32, Error> {
        let signers = Self::signers(env)?;
        signers
            .iter()
            .find(|s| &s.address == who)
            .map(|s| s.weight)
            .ok_or(Error::NotASigner)
    }

    fn threshold(env: &Env) -> Result<u32, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)
    }

    fn load_proposal(env: &Env, id: u64) -> Result<MsProposal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(id))
            .ok_or(Error::NotFound)
    }

    fn require_signer(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let signers = Self::signers(env)?;
        if !signers.iter().any(|s| &s.address == caller) {
            return Err(Error::NotASigner);
        }
        Ok(())
    }

    fn require_not_locked(env: &Env) -> Result<(), Error> {
        let locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::EmergencyLock)
            .unwrap_or(false);
        if locked {
            return Err(Error::EmergencyLock);
        }
        Ok(())
    }

    /// Build the deterministic payload `(nonce, calls)` that every approver's
    /// signature must cover, so a signature can never be replayed against a
    /// different batch or a reused nonce.
    fn batch_payload(env: &Env, nonce: u64, calls: &Vec<BatchCall>) -> Vec<Val> {
        let nonce_val: Val = nonce.into_val(env);
        let calls_val: Val = calls.to_val();
        vec![env, nonce_val, calls_val]
    }

    /// Verify `caller` plus every distinct `signatories` entry against `args`
    /// and accumulate their voting weight.
    ///
    /// Each address must be a registered signer; the Soroban host performs the
    /// cryptographic verification through [`Address::require_auth_for_args`],
    /// binding every signature to the exact payload. Repeated entries — the
    /// caller included — are verified and counted once, so one key can never
    /// stack its own weight.
    fn accumulate_weight(
        env: &Env,
        signers: &Vec<SignerWeight>,
        caller: &Address,
        signatories: &Vec<Address>,
        args: &Vec<Val>,
    ) -> Result<u32, Error> {
        let caller_weight = signers
            .iter()
            .find(|s| &s.address == caller)
            .map(|s| s.weight)
            .ok_or(Error::NotASigner)?;
        caller.require_auth_for_args(args.clone());
        let mut total: i128 = caller_weight as i128;
        let mut seen = Vec::new(env);
        seen.push_back(caller.clone());
        for who in signatories.iter() {
            let weight = signers
                .iter()
                .find(|s| s.address == who)
                .map(|s| s.weight)
                .ok_or(Error::NotASigner)?;
            if seen.contains(&who) {
                continue;
            }
            seen.push_back(who.clone());
            who.require_auth_for_args(args.clone());
            total = checked_add(total, weight as i128)?;
        }
        Self::to_weight(total)
    }

    /// Invoke a single batch call inside a Soroban error-handling boundary so a
    /// failure can be caught and the whole batch reverted atomically instead of
    /// aborting with an opaque trap. Returns the callee's own contract error
    /// when it is one of ours, otherwise [`Error::BatchCallFailed`].
    fn execute_call(env: &Env, call: &BatchCall) -> Result<(), Error> {
        match env.try_invoke_contract::<Val, Error>(&call.contract, &call.func, call.args.clone()) {
            Ok(Ok(_)) => Ok(()),
            // A raw `Val` always decodes, so this arm is unreachable in
            // practice; kept for exhaustiveness.
            Ok(Err(_)) => Err(Error::BatchCallFailed),
            // The callee exited with a contract error — surface it precisely.
            Err(Ok(e)) => Err(e),
            // System-level failure (panic / abort / unknown error code).
            Err(Err(_)) => Err(Error::BatchCallFailed),
        }
    }

    /// Shared proposal path for every governance change: authorize, validate
    /// against live state, then park the change behind the timelock.
    fn propose_change(env: &Env, caller: &Address, change: GovernanceChange) -> Result<u64, Error> {
        Self::require_not_locked(env)?;
        Self::require_governor(env, caller)?;
        // Fail fast: a change that could not apply today is never parked.
        Self::validate_change(env, &change)?;

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ChangeCount)
            .unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let now = env.ledger().timestamp();
        let eta = now
            .checked_add(Self::timelock_delay(env))
            .ok_or(Error::Overflow)?;
        let expires_at = eta
            .checked_add(GOVERNANCE_GRACE_PERIOD)
            .ok_or(Error::Overflow)?;
        let kind = Self::change_kind(&change);
        let pending = PendingChange {
            proposer: caller.clone(),
            change,
            proposed_at: now,
            eta,
            expires_at,
            executed: false,
            cancelled: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Change(id), &pending);
        Self::bump_change(env, id);
        env.storage().instance().set(&DataKey::ChangeCount, &count);
        Self::bump_instance(env);

        env.events().publish(
            (symbol_short!("govchange"), symbol_short!("proposed")),
            (id, caller.clone(), kind, eta),
        );
        Ok(id)
    }

    /// Check a governance change against the live signer set and threshold.
    /// Run both at proposal time and immediately before execution.
    fn validate_change(env: &Env, change: &GovernanceChange) -> Result<(), Error> {
        let signers = Self::signers(env)?;
        let threshold = Self::threshold(env)?;
        let total = Self::total_weight(&signers)? as i128;
        match change {
            GovernanceChange::Threshold(new_threshold) => {
                Self::validate_threshold(*new_threshold, Self::to_weight(total)?)
            }
            GovernanceChange::SignerWeight(signer, weight) => {
                if *weight == 0 {
                    return Err(Error::InvalidSignerWeight);
                }
                let current = Self::weight_of(env, signer)?;
                let new_total = checked_add(checked_sub(total, current as i128)?, *weight as i128)?;
                Self::to_weight(new_total)?;
                if new_total < threshold as i128 {
                    return Err(Error::InvalidThreshold);
                }
                Ok(())
            }
            GovernanceChange::AddSigner(signer, weight) => {
                if *weight == 0 {
                    return Err(Error::InvalidSignerWeight);
                }
                if signers.iter().any(|s| &s.address == signer) {
                    return Err(Error::AlreadyExists);
                }
                if signers.len() >= MAX_SIGNERS {
                    return Err(Error::TooManySigners);
                }
                // Total weight only grows here, so the threshold stays
                // satisfiable; the check is purely an overflow guard.
                Self::to_weight(checked_add(total, *weight as i128)?)?;
                Ok(())
            }
            GovernanceChange::RemoveSigner(signer) => {
                let removed = Self::weight_of(env, signer)?;
                if checked_sub(total, removed as i128)? < threshold as i128 {
                    return Err(Error::InvalidThreshold);
                }
                Ok(())
            }
            GovernanceChange::TimelockDelay(delay) => {
                if *delay < MIN_TIMELOCK_DELAY || *delay > MAX_TIMELOCK_DELAY {
                    return Err(Error::InvalidInput);
                }
                Ok(())
            }
        }
    }

    /// Commit a validated governance change and emit the matching effect event,
    /// so consumers of the pre-timelock events keep working unchanged.
    fn apply_change(env: &Env, change: &GovernanceChange) -> Result<(), Error> {
        match change {
            GovernanceChange::Threshold(new_threshold) => {
                env.storage()
                    .instance()
                    .set(&DataKey::Threshold, new_threshold);
                env.events().publish(
                    (symbol_short!("threshold"), symbol_short!("changed")),
                    *new_threshold,
                );
            }
            GovernanceChange::SignerWeight(signer, weight) => {
                let mut signers = Self::signers(env)?;
                let idx = Self::index_of(&signers, signer)?;
                let mut updated = signers.get(idx).unwrap();
                updated.weight = *weight;
                signers.set(idx, updated);
                env.storage().instance().set(&DataKey::Signers, &signers);
                env.events().publish(
                    (symbol_short!("signer"), symbol_short!("weight")),
                    (signer.clone(), *weight),
                );
            }
            GovernanceChange::AddSigner(signer, weight) => {
                let mut signers = Self::signers(env)?;
                signers.push_back(SignerWeight {
                    address: signer.clone(),
                    weight: *weight,
                });
                env.storage().instance().set(&DataKey::Signers, &signers);
                env.events().publish(
                    (symbol_short!("signer"), symbol_short!("added")),
                    (signer.clone(), *weight),
                );
            }
            GovernanceChange::RemoveSigner(signer) => {
                let mut signers = Self::signers(env)?;
                let idx = Self::index_of(&signers, signer)?;
                signers.remove(idx);
                env.storage().instance().set(&DataKey::Signers, &signers);
                env.events().publish(
                    (symbol_short!("signer"), symbol_short!("removed")),
                    signer.clone(),
                );
            }
            GovernanceChange::TimelockDelay(delay) => {
                env.storage().instance().set(&DataKey::TimelockDelay, delay);
                env.events().publish(
                    (symbol_short!("timelock"), symbol_short!("changed")),
                    *delay,
                );
            }
        }
        Self::bump_instance(env);
        Ok(())
    }

    /// Short symbol describing a change, published with every governance event
    /// so indexers can filter without decoding the payload.
    fn change_kind(change: &GovernanceChange) -> Symbol {
        match change {
            GovernanceChange::Threshold(_) => symbol_short!("threshold"),
            GovernanceChange::SignerWeight(_, _) => symbol_short!("weight"),
            GovernanceChange::AddSigner(_, _) => symbol_short!("addsigner"),
            GovernanceChange::RemoveSigner(_) => symbol_short!("rmsigner"),
            GovernanceChange::TimelockDelay(_) => symbol_short!("timelock"),
        }
    }

    fn index_of(signers: &Vec<SignerWeight>, signer: &Address) -> Result<u32, Error> {
        signers
            .iter()
            .position(|s| &s.address == signer)
            .map(|i| i as u32)
            .ok_or(Error::NotASigner)
    }

    fn load_change(env: &Env, id: u64) -> Result<PendingChange, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Change(id))
            .ok_or(Error::NotFound)
    }

    /// A change may only be executed or cancelled once.
    fn require_change_open(pending: &PendingChange) -> Result<(), Error> {
        if pending.executed || pending.cancelled {
            return Err(Error::InvalidProposalState);
        }
        Ok(())
    }

    fn timelock_delay(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::TimelockDelay)
            .unwrap_or(MIN_TIMELOCK_DELAY)
    }

    /// Authorize a governance caller. Distinct from [`Self::require_signer`] so
    /// governance denials surface the dedicated
    /// [`Error::UnauthorizedModification`] code.
    fn require_governor(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let signers = Self::signers(env)?;
        if !signers.iter().any(|s| &s.address == caller) {
            return Err(Error::UnauthorizedModification);
        }
        Ok(())
    }

    fn bump_change(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Change(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn validate_threshold(threshold: u32, n: u32) -> Result<(), Error> {
        if threshold < MIN_THRESHOLD || threshold > n {
            return Err(Error::InvalidThreshold);
        }
        Ok(())
    }

    fn assert_unique(signers: &Vec<SignerWeight>) -> Result<(), Error> {
        let len = signers.len();
        let mut i = 0;
        while i < len {
            let a = signers.get(i).unwrap().address.clone();
            let mut j = i + 1;
            while j < len {
                if a == signers.get(j).unwrap().address {
                    return Err(Error::InvalidInput);
                }
                j += 1;
            }
            i += 1;
        }
        Ok(())
    }

    fn bump_proposal(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Proposal(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
}

#[cfg(test)]
mod test;
