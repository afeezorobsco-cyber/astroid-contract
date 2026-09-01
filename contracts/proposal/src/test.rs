#![cfg(test)]
extern crate std;

use crate::{ProposalContext, ProposalContract, ProposalContractClient, ProposalState};
use astroid_shared::constants::MAX_DEPENDENCIES;
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, String, Vec};

struct Harness {
    env: Env,
    client: ProposalContractClient<'static>,
    proposer: Address,
    approvers: std::vec::Vec<Address>,
}

fn setup(num_approvers: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register_contract(None, ProposalContract);
    let client = ProposalContractClient::new(&env, &contract_id);
    client.initialize();

    let proposer = Address::generate(&env);
    let mut approvers = std::vec::Vec::new();
    for _ in 0..num_approvers {
        approvers.push(Address::generate(&env));
    }
    Harness {
        env,
        client,
        proposer,
        approvers,
    }
}

fn approver_vec(h: &Harness) -> Vec<Address> {
    let mut v = Vec::new(&h.env);
    for a in &h.approvers {
        v.push_back(a.clone());
    }
    v
}

/// Create an independent proposal (no prerequisites).
fn create(h: &Harness, threshold: u32, expires_at: u64) -> u64 {
    create_with_deps(h, threshold, expires_at, &[])
}

/// Create a proposal that depends on `deps`.
fn create_with_deps(h: &Harness, threshold: u32, expires_at: u64, deps: &[u64]) -> u64 {
    h.client.create(
        &h.proposer,
        &ProposalContext {
            org: String::from_str(&h.env, "acme"),
            wallet: String::from_str(&h.env, "wallet-1"),
            policy: String::from_str(&h.env, "policy-1"),
            tx_ref: String::from_str(&h.env, "tx-ref-1"),
        },
        &approver_vec(h),
        &dep_vec(h, deps),
        &threshold,
        &soroban_sdk::vec![&h.env],
        &expires_at,
        &0,
    )
}

/// `create_with_deps` in its fallible form, for the rejection paths.
fn try_create_with_deps(h: &Harness, deps: &[u64]) -> Result<u64, Error> {
    h.client
        .try_create(
            &h.proposer,
            &ProposalContext {
                org: String::from_str(&h.env, "acme"),
                wallet: String::from_str(&h.env, "wallet-1"),
                policy: String::from_str(&h.env, "policy-1"),
                tx_ref: String::from_str(&h.env, "tx-ref-1"),
            },
            &approver_vec(h),
            &dep_vec(h, deps),
            &2,
            &soroban_sdk::vec![&h.env],
            &0,
            &0,
        )
        .map(|ok| ok.unwrap())
        .map_err(|err| err.unwrap())
}

fn dep_vec(h: &Harness, deps: &[u64]) -> Vec<u64> {
    let mut v = Vec::new(&h.env);
    for d in deps {
        v.push_back(*d);
    }
    v
}

/// Drive a proposal all the way to `Executed`.
fn approve_and_execute(h: &Harness, id: u64) {
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.execute(&h.proposer, &id);
}

#[test]
fn create_starts_pending() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn full_lifecycle_to_closed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    let approvals = h.client.approve(&h.approvers[1], &id);
    assert_eq!(approvals, 2);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);

    h.client.close(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Closed);
}

#[test]
fn execute_before_approved_fails() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id); // only 1 of 2
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::ProposalNotApproved)));
}

#[test]
fn non_approver_cannot_approve() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    let stranger = Address::generate(&h.env);
    let res = h.client.try_approve(&stranger, &id);
    assert_eq!(res, Err(Ok(Error::NotAnApprover)));
}

#[test]
fn double_approval_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    let res = h.client.try_approve(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn reject_moves_to_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.reject(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Rejected);
    // Cannot approve a rejected proposal.
    let res = h.client.try_approve(&h.approvers[1], &id);
    assert_eq!(res, Err(Ok(Error::InvalidProposalState)));
}

#[test]
fn only_proposer_can_cancel() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    let res = h.client.try_cancel(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    h.client.cancel(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Cancelled);
}

#[test]
fn expired_proposal_cannot_be_approved() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    // Advance beyond expiry.
    h.env.ledger().set_timestamp(6_000);
    let res = h.client.try_approve(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::ProposalExpired)));
    // The failed approval is rolled back by the host, so the proposal is still
    // Pending on-chain. The terminal `Expired` transition is recorded only via
    // the permissionless `expire()` path (see `explicit_expire_transition`).
    assert_eq!(h.client.state(&id), ProposalState::Pending);
    h.client.expire(&id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn explicit_expire_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    // Cannot expire before deadline.
    let early = h.client.try_expire(&id);
    assert_eq!(early, Err(Ok(Error::InvalidProposalState)));
    h.env.ledger().set_timestamp(6_000);
    h.client.expire(&id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn create_with_bad_threshold_fails() {
    let h = setup(2);
    // threshold 3 > 2 approvers
    let res = h.client.try_create(
        &h.proposer,
        &ProposalContext {
            org: String::from_str(&h.env, "acme"),
            wallet: String::from_str(&h.env, "wallet-1"),
            policy: String::from_str(&h.env, "policy-1"),
            tx_ref: String::from_str(&h.env, "tx-ref-1"),
        },
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &3,
        &soroban_sdk::vec![&h.env],
        &5_000,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn create_with_past_expiry_fails() {
    let h = setup(2);
    let res = h.client.try_create(
        &h.proposer,
        &ProposalContext {
            org: String::from_str(&h.env, "acme"),
            wallet: String::from_str(&h.env, "wallet-1"),
            policy: String::from_str(&h.env, "policy-1"),
            tx_ref: String::from_str(&h.env, "tx-ref-1"),
        },
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &1,
        &soroban_sdk::vec![&h.env],
        &500, // in the past (now = 1000)
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

// ---------------------------------------------------------------------------
// Dependency chaining
// ---------------------------------------------------------------------------

#[test]
fn independent_proposal_declares_no_dependencies() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(h.client.dependencies(&id), dep_vec(&h, &[]));
    assert!(h.client.dependencies_met(&id));
}

#[test]
fn chain_executes_in_order() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);
    let third = create_with_deps(&h, 2, 5_000, &[second]);

    assert_eq!(h.client.dependencies(&second), dep_vec(&h, &[first]));

    approve_and_execute(&h, first);
    assert_eq!(h.client.state(&first), ProposalState::Executed);

    assert!(h.client.dependencies_met(&second));
    approve_and_execute(&h, second);

    assert!(h.client.dependencies_met(&third));
    approve_and_execute(&h, third);
    assert_eq!(h.client.state(&third), ProposalState::Executed);
}

#[test]
fn execution_blocked_until_prerequisite_executes() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // Fully approved, but its prerequisite has not executed.
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(h.client.state(&second), ProposalState::Approved);
    assert!(!h.client.dependencies_met(&second));

    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    // The blocked proposal stays Approved and remains executable later.
    assert_eq!(h.client.state(&second), ProposalState::Approved);

    approve_and_execute(&h, first);
    h.client.execute(&h.proposer, &second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);
}

#[test]
fn approval_is_not_blocked_by_dependencies() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // A dependent proposal can still gather approvals ahead of its
    // prerequisite; only execution is sequenced.
    h.client.approve(&h.approvers[0], &second);
    let approvals = h.client.approve(&h.approvers[1], &second);
    assert_eq!(approvals, 2);
    assert_eq!(h.client.state(&second), ProposalState::Approved);
}

#[test]
fn all_prerequisites_must_execute() {
    let h = setup(3);
    let a = create(&h, 2, 5_000);
    let b = create(&h, 2, 5_000);
    let dependent = create_with_deps(&h, 2, 5_000, &[a, b]);

    h.client.approve(&h.approvers[0], &dependent);
    h.client.approve(&h.approvers[1], &dependent);

    approve_and_execute(&h, a);
    // One of two prerequisites done is not enough.
    assert!(!h.client.dependencies_met(&dependent));
    assert_eq!(
        h.client.try_execute(&h.proposer, &dependent),
        Err(Ok(Error::PrerequisiteNotMet))
    );

    approve_and_execute(&h, b);
    h.client.execute(&h.proposer, &dependent);
    assert_eq!(h.client.state(&dependent), ProposalState::Executed);
}

#[test]
fn failed_prerequisite_blocks_the_chain_permanently() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    h.client.approve(&h.approvers[0], &first);
    h.client.approve(&h.approvers[1], &first);
    h.client.fail(&h.proposer, &first);
    assert_eq!(h.client.state(&first), ProposalState::Failed);

    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert!(!h.client.dependencies_met(&second));
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    // Failed is terminal, so the prerequisite can never be satisfied.
    assert_eq!(
        h.client.try_execute(&h.proposer, &first),
        Err(Ok(Error::ProposalNotApproved))
    );
}

#[test]
fn cancelled_prerequisite_blocks_the_chain() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);
    h.client.cancel(&h.proposer, &first);

    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
}

#[test]
fn closed_prerequisite_still_satisfies_dependents() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    approve_and_execute(&h, first);
    // Tidying an executed prerequisite away must not block its dependents.
    h.client.close(&h.proposer, &first);
    assert_eq!(h.client.state(&first), ProposalState::Closed);

    assert!(h.client.dependencies_met(&second));
    approve_and_execute(&h, second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);
}

#[test]
fn self_reference_is_rejected_as_circular() {
    let h = setup(3);
    // The next id would be 1, so depending on 1 is a self-reference.
    assert_eq!(
        try_create_with_deps(&h, &[1]),
        Err(Error::CircularDependencyDetected)
    );
}

#[test]
fn forward_reference_is_rejected_as_circular() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    // Depending on a not-yet-created proposal is the only way an edge could
    // point forward, which is the only way a cycle could form.
    assert_eq!(
        try_create_with_deps(&h, &[first + 5]),
        Err(Error::CircularDependencyDetected)
    );
}

#[test]
fn duplicate_dependencies_are_collapsed() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let dependent = create_with_deps(&h, 2, 5_000, &[first, first, first]);
    // Stored once, so execution reads the prerequisite exactly once.
    assert_eq!(h.client.dependencies(&dependent), dep_vec(&h, &[first]));
}

#[test]
fn too_many_dependencies_rejected() {
    let h = setup(3);
    let mut deps = std::vec::Vec::new();
    for _ in 0..=MAX_DEPENDENCIES {
        deps.push(create(&h, 2, 5_000));
    }
    assert_eq!(try_create_with_deps(&h, &deps), Err(Error::InvalidInput));
}

#[test]
fn fail_requires_approval_and_the_proposer() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);

    // Pending, not yet approved.
    assert_eq!(
        h.client.try_fail(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );

    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(
        h.client.try_fail(&h.approvers[0], &id),
        Err(Ok(Error::Unauthorized))
    );

    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

#[test]
fn test_cancellation_grace_window() {
    let h = setup(3);
    h.env.ledger().set_timestamp(100);
    let id = h.client.create(
        &h.proposer,
        &ProposalContext {
            org: String::from_str(&h.env, "org"),
            wallet: String::from_str(&h.env, "w1"),
            policy: String::from_str(&h.env, "p1"),
            tx_ref: String::from_str(&h.env, "tx1"),
        },
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &2,
        &soroban_sdk::vec![&h.env],
        &0,
        &50, // 50 seconds grace period
    );

    // Fast forward 51 seconds
    h.env.ledger().set_timestamp(151);

    // Cancel should fail
    let res = h.client.try_cancel(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::CancellationWindowClosed)));

    // Create a new one and cancel inside window
    let id2 = h.client.create(
        &h.proposer,
        &ProposalContext {
            org: String::from_str(&h.env, "org"),
            wallet: String::from_str(&h.env, "w1"),
            policy: String::from_str(&h.env, "p1"),
            tx_ref: String::from_str(&h.env, "tx1"),
        },
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &2,
        &soroban_sdk::vec![&h.env],
        &0,
        &50,
    );

    h.env.ledger().set_timestamp(160);
    h.client.cancel(&h.proposer, &id2); // works since 160 < 151 + 50 (created at 151)

    assert_eq!(h.client.state(&id2), crate::ProposalState::Cancelled);
}
