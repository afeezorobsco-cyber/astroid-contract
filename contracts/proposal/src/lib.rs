#![no_std]
//! # Astroid Proposal Contract
//!
//! Represents an action awaiting approval and drives it through the lifecycle
//! (PRD Doc 7 §Proposal):
//!
//! ```text
//! Created ─▶ Pending ─▶ Approved ─▶ Executed
//!    │          │           │
//!    ▼          ▼           ▼
//!  Cancelled  Rejected    Closed
//!            / Expired
//! ```
//!
//! A proposal links off-chain context — `wallet`, `policy` and `org` — so the
//! backend can reconstruct why money moved. The
//! contract records an explicit approver allow-list and an approval threshold;
//! reaching the threshold moves the proposal to `Approved`, after which it may
//! be `Executed` (marked done) and finally `Closed`. An approved proposal whose
//! off-chain action did not go through is marked `Failed`, a terminal state.
//!
//! ## Dependency chaining
//!
//! A proposal may declare prerequisite proposals it depends on. `execute` then
//! refuses to run until every prerequisite has executed, which is what lets a
//! multi-step protocol upgrade or a staged asset allocation be sequenced
//! correctly: each step is its own proposal, approved on its own merits, but
//! the steps can only fire in order.
//!
//! ```text
//! #1 fund escrow ──▶ #2 migrate balances ──▶ #3 retire old module
//!                    (depends on #1)          (depends on #2)
//! ```
//!
//! The graph is acyclic by construction — see [`ProposalContract::create`] —
//! and a dependency that would close a cycle is rejected at creation time with
//! [`Error::CircularDependencyDetected`].
//!
//! Functions: `create`, `approve`, `reject`, `cancel`, `expire`, `execute`,
//! `fail`, `close`.

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_APPROVERS, MAX_DEPENDENCIES,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use astroid_shared::types::AssetAmount;
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenClient, Address, Env, String,
    Vec,
};

/// Proposal lifecycle state.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalState {
    Created = 0,
    Pending = 1,
    Approved = 2,
    Executed = 3,
    Closed = 4,
    Rejected = 5,
    Cancelled = 6,
    Expired = 7,
    /// Approved, but the action it authorized did not go through. Terminal, and
    /// deliberately distinct from `Executed` so a dependent proposal stays
    /// blocked rather than inheriting a broken prerequisite.
    Failed = 8,
}

impl ProposalState {
    /// Whether a proposal in this state has carried out its action, and so can
    /// satisfy a dependent proposal's prerequisite.
    ///
    /// `Closed` counts: it is only reachable from `Executed`, and tidying an
    /// executed proposal away must not retroactively block its dependents.
    pub fn has_executed(self) -> bool {
        matches!(self, ProposalState::Executed | ProposalState::Closed)
    }
}

/// Off-chain context bundled with every proposal so the backend can
/// reconstruct why money moved.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalContext {
    pub org: String,
    pub wallet: String,
    pub policy: String,
    pub tx_ref: String,
}

/// Stored proposal record. `approvers` is the allow-list of addresses eligible
/// to approve; `threshold` approvals move it to `Approved`. `dependencies` are
/// the ids of proposals that must have executed before this one may execute.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub proposer: Address,
    pub context: ProposalContext,
    pub approvers: Vec<Address>,
    /// Prerequisite proposal ids, deduplicated and each strictly less than this
    /// proposal's own id. Empty for a proposal with no dependencies.
    pub dependencies: Vec<u64>,
    pub threshold: u32,
    pub approvals: u32,
    pub state: ProposalState,
    pub created_at: u64,
    pub deposit: Vec<AssetAmount>,
    pub expires_at: u64,
    pub grace_period: u64,
}

impl Proposal {
    pub fn is_expired(&self, env: &Env) -> bool {
        self.expires_at != 0 && env.ledger().timestamp() >= self.expires_at
    }

    pub fn is_active(&self, env: &Env) -> bool {
        !self.is_expired(env)
            && matches!(self.state, ProposalState::Pending | ProposalState::Approved)
    }

    pub fn can_execute(&self, env: &Env) -> bool {
        self.is_active(env) && self.state == ProposalState::Approved
    }
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    ProposalCount,
    Proposal(u64),
    Approval(u64, Address),
}

#[contract]
pub struct ProposalContract;

#[contractimpl]
impl ProposalContract {
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
    /// `wasm_hash` must be approved for [`ModuleKind::Proposal`] in the registry. Any
    /// other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Proposal,
            wasm_hash,
        )
    }
    /// Initialize the id counter. Idempotent-guarded.
    pub fn initialize(env: Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::ProposalCount) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::ProposalCount, &0u64);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Create a proposal in `Pending` state. `proposer` must authorize. The
    /// approver allow-list must be non-empty and `threshold` within its size.
    ///
    /// `dependencies` lists prerequisite proposals that must have executed
    /// before this one may execute; pass an empty vector for an independent
    /// proposal. Each entry must name an existing proposal, and duplicates are
    /// collapsed so a prerequisite is read exactly once at execution time.
    ///
    /// **Acyclicity.** Proposal ids are assigned from a monotonic counter, and a
    /// dependency must name a proposal that already exists — so every edge in
    /// the graph points from a higher id to a strictly lower one, and a cycle
    /// would require an edge pointing forward. That is exactly what the
    /// `dependency >= id` check rejects, with
    /// [`Error::CircularDependencyDetected`]. Self-reference is the degenerate
    /// case of the same check. Because every edge strictly decreases the id,
    /// no sequence of edges can return to its starting proposal, so the graph
    /// is a DAG by construction and no traversal is needed.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        proposer: Address,
        context: ProposalContext,
        approvers: Vec<Address>,
        dependencies: Vec<u64>,
        threshold: u32,
        deposit: Vec<AssetAmount>,
        expires_at: u64,
        grace_period: u64,
    ) -> Result<u64, Error> {
        proposer.require_auth();
        require_non_empty(&context.org)?;
        let n = approvers.len();
        if n == 0 || n > MAX_APPROVERS {
            return Err(Error::InvalidInput);
        }
        if threshold == 0 || threshold > n {
            return Err(Error::InvalidThreshold);
        }
        if let Some(dep) = deposit.first() {
            if dep.amount <= 0 {
                return Err(Error::InvalidAmount);
            }
            TokenClient::new(&env, &dep.asset).transfer(
                &proposer,
                &env.current_contract_address(),
                &dep.amount,
            );
        }
        if expires_at != 0 && expires_at <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }

        if dependencies.len() > MAX_DEPENDENCIES {
            return Err(Error::InvalidInput);
        }

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        // Validate the declared prerequisites and collapse duplicates, so that
        // `execute` reads each prerequisite exactly once.
        let mut deps: Vec<u64> = Vec::new(&env);
        for dep in dependencies.iter() {
            // Any edge that does not point strictly backwards would close a
            // cycle (or be a self-reference); see the acyclicity note above.
            if dep >= id {
                return Err(Error::CircularDependencyDetected);
            }
            if !env.storage().persistent().has(&DataKey::Proposal(dep)) {
                return Err(Error::NotFound);
            }
            if !deps.contains(dep) {
                deps.push_back(dep);
            }
        }

        let proposal = Proposal {
            proposer: proposer.clone(),
            context,
            approvers,
            dependencies: deps,
            threshold,
            approvals: 0,
            deposit,
            state: ProposalState::Pending,
            created_at: env.ledger().timestamp(),
            expires_at,
            grace_period,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        Self::bump(&env, id);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCount, &count);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("created")),
            (id, proposer),
        );
        Ok(id)
    }

    /// Approve a proposal. Caller must be on the approver allow-list and may
    /// approve only once. Reaching `threshold` transitions to `Approved`.
    pub fn approve(env: Env, caller: Address, id: u64) -> Result<u32, Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if proposal.is_expired(&env) {
            return Err(Error::ProposalExpired);
        }
        if proposal.state != ProposalState::Pending {
            return Err(Error::InvalidProposalState);
        }
        if !proposal.approvers.contains(&caller) {
            return Err(Error::NotAnApprover);
        }
        let akey = DataKey::Approval(id, caller.clone());
        if env.storage().persistent().get(&akey).unwrap_or(false) {
            return Err(Error::AlreadySigned);
        }
        env.storage().persistent().set(&akey, &true);
        proposal.approvals = checked_add(proposal.approvals as i128, 1)? as u32;
        if proposal.approvals >= proposal.threshold {
            proposal.state = ProposalState::Approved;
        }
        Self::store(&env, id, &proposal);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("approved")),
            (id, caller, proposal.approvals),
        );
        Ok(proposal.approvals)
    }

    /// Reject a proposal. Any approver may reject a pending proposal, which
    /// moves it to the terminal `Rejected` state.
    pub fn reject(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if proposal.state != ProposalState::Pending {
            return Err(Error::InvalidProposalState);
        }
        if !proposal.approvers.contains(&caller) {
            return Err(Error::NotAnApprover);
        }
        proposal.state = ProposalState::Rejected;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(&env, id, &proposal);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("rejected")),
            (id, caller),
        );
        Ok(())
    }

    /// Cancel a proposal. Only the original proposer may cancel, and only before
    /// it is executed/closed.
    pub fn cancel(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if matches!(
            proposal.state,
            ProposalState::Executed | ProposalState::Closed | ProposalState::Cancelled
        ) {
            return Err(Error::InvalidProposalState);
        }
        if proposal.grace_period != 0
            && env.ledger().timestamp() > proposal.created_at + proposal.grace_period
        {
            return Err(Error::CancellationWindowClosed);
        }
        proposal.state = ProposalState::Cancelled;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("cancelled")), id);
        Ok(())
    }

    /// Mark a proposal expired if its deadline has passed. Permissionless
    /// (anyone may trigger the transition; state gate protects correctness).
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut proposal = Self::load(&env, id)?;
        if !matches!(
            proposal.state,
            ProposalState::Pending | ProposalState::Approved
        ) {
            return Err(Error::InvalidProposalState);
        }
        if !proposal.is_expired(&env) {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Expired;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("expired")), id);
        Ok(())
    }

    /// Execute an approved proposal. Only the proposer may execute (the actual
    /// value movement happens in the wallet/treasury; this records completion).
    ///
    /// Every declared prerequisite must have executed first, otherwise the call
    /// fails with [`Error::PrerequisiteNotMet`] and nothing changes. This is
    /// checked after approval and expiry so that a proposal blocked only by its
    /// chain reports the dependency rather than a less specific error.
    /// Purge an expired proposal from storage to reclaim space.
    pub fn cleanup_expired(env: Env, id: u64) -> Result<(), Error> {
        let proposal = Self::load(&env, id)?;
        if proposal.expires_at == 0 || env.ledger().timestamp() < proposal.expires_at {
            return Err(Error::InvalidProposalState);
        }
        env.storage().persistent().remove(&DataKey::Proposal(id));
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("cleaned")), id);
        Ok(())
    }

    pub fn execute(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if proposal.is_expired(&env) {
            return Err(Error::ProposalExpired);
        }
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if proposal.state != ProposalState::Approved {
            return Err(Error::ProposalNotApproved);
        }
        Self::ensure_dependencies_met(&env, &proposal)?;
        proposal.state = ProposalState::Executed;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("executed")), id);
        Ok(())
    }

    /// Mark an approved proposal as `Failed` (terminal). Only the proposer may
    /// do so. Recording the failure explicitly keeps a broken step visible to
    /// anything that depends on it: a `Failed` prerequisite never satisfies a
    /// dependent proposal, so the chain stops instead of silently continuing.
    pub fn fail(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if proposal.state != ProposalState::Approved {
            return Err(Error::ProposalNotApproved);
        }
        proposal.state = ProposalState::Failed;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("failed")), id);
        Ok(())
    }

    /// Close an executed proposal (terminal). Only the proposer may close.
    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if proposal.state != ProposalState::Executed {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Closed;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("closed")), id);
        Ok(())
    }

    // --- views ---

    pub fn get(env: Env, id: u64) -> Result<Proposal, Error> {
        Self::load(&env, id)
    }

    pub fn state(env: Env, id: u64) -> Result<ProposalState, Error> {
        Ok(Self::load(&env, id)?.state)
    }

    /// The prerequisite proposal ids this proposal declares.
    pub fn dependencies(env: Env, id: u64) -> Result<Vec<u64>, Error> {
        Ok(Self::load(&env, id)?.dependencies)
    }

    /// Whether every prerequisite has executed — the same question `execute`
    /// asks, exposed so callers can check before spending a transaction on it.
    pub fn dependencies_met(env: Env, id: u64) -> Result<bool, Error> {
        let proposal = Self::load(&env, id)?;
        Ok(Self::ensure_dependencies_met(&env, &proposal).is_ok())
    }

    // --- internal helpers ---

    fn load(env: &Env, id: u64) -> Result<Proposal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(id))
            .ok_or(Error::NotFound)
    }

    fn store(env: &Env, id: u64, proposal: &Proposal) {
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), proposal);
        Self::bump(env, id);
    }

    /// Require that every prerequisite proposal has executed.
    ///
    /// Dependencies are deduplicated at creation time and each entry is one
    /// storage read, so a check costs exactly as many reads as the proposal has
    /// distinct prerequisites — and short-circuits on the first unmet one. A
    /// prerequisite that has been cancelled, rejected, expired or explicitly
    /// marked `Failed` can never become executed, but it is reported the same
    /// way: the dependent proposal simply cannot run.
    fn ensure_dependencies_met(env: &Env, proposal: &Proposal) -> Result<(), Error> {
        for dep in proposal.dependencies.iter() {
            let prerequisite = Self::load(env, dep)?;
            if !prerequisite.state.has_executed() {
                return Err(Error::PrerequisiteNotMet);
            }
        }
        Ok(())
    }

    fn bump(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Proposal(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

#[cfg(test)]
mod test;
