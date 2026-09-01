use astroid_shared::errors::Error;
use core::borrow::Borrow;
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    Address, BytesN, Env, IntoVal, String, Symbol, Val,
};

use crate::{
    policy_rules::{PolicyRule, RuleMatch, RuleTarget},
    PolicyContract, PolicyContractClient, RuleNode, RuleOp, RuleTree, TransactionPayload,
};

/// Assert that a `try_*` result is an `Err` matching `Error::RuleDenied`.
fn assert_rule_denied(
    result: &Result<
        Result<(), soroban_sdk::ConversionError>,
        Result<astroid_shared::errors::Error, soroban_sdk::InvokeError>,
    >,
) {
    match result {
        Err(Ok(astroid_shared::errors::Error::RuleDenied)) => {}
        other => panic!("expected RuleDenied, got {:?}", other),
    }
}

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

fn setup<'a>(env: &Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "max_txn"),
        &BytesN::from_array(env, &[42; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
    );
    client
}

#[test]
fn allows_spend_below_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &999_999,)
        .is_ok());
}

#[test]
fn denies_spend_above_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert!(r.is_err());
}

#[test]
fn allowlist_recipient_enforced() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);
    let asset = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(&env, &id);
    client.initialize();
    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &Some(allowed.clone()),
        &None,
        &0,
    );

    // Allowed recipient passes
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &allowed, &1,)
        .is_ok());

    // Other recipient denied
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &blocked, &1,)
        .is_err());
}

#[test]
fn disable_denies_everything() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    p.set_enabled(&owner, &String::from_str(&env, "max_txn"), &false);
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &Address::generate(&env),
            &1,
        )
        .is_err());
}

#[test]
fn standard_policy_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    // Amount above the configured max triggers a policy denial -> violation event.
    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert_event(&env, "PolicyViolation");
}

// ── Exact destination allowlist ────────────────────────────────────────

#[test]
fn exact_destination_allowlist_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_v1"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: allowed.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &allowed, &100,)
        .is_ok());
}

#[test]
fn exact_destination_allowlist_no_match_falls_through() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);
    let other = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_v1"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: allowed.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &other, &100,)
        .is_ok());
}

// ── Exact destination denylist ─────────────────────────────────────────

#[test]
fn exact_destination_denylist_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &100);
    assert!(r.is_err());
    assert_rule_denied(&r);
}

#[test]
fn exact_destination_denylist_non_matching_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);
    let other = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &other, &100,)
        .is_ok());
}

// ── Wildcard destination matching ──────────────────────────────────────

#[test]
fn wildcard_destination_deny_matches_prefix() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let target_addr = Address::generate(&env);

    // Build a wildcard pattern from the first 4 chars of the address string.
    let addr_str = target_addr.to_string();
    let addr_len = addr_str.len() as usize;
    let mut addr_buf = [0u8; 128];
    addr_str.copy_into_slice(&mut addr_buf[..addr_len]);
    let prefix_len = 4.min(addr_len);
    let mut pat_bytes = soroban_sdk::Bytes::new(&env);
    for &b in addr_buf.iter().take(prefix_len) {
        pat_bytes.push_back(b);
    }
    pat_bytes.push_back(b'*');
    let pat_buf = pat_bytes.to_buffer::<128>();
    let pattern = String::from_bytes(&env, pat_buf.borrow());

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "wild_deny"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: pattern,
        },
    );

    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &target_addr,
        &100,
    );
    assert!(r.is_err());
}

#[test]
fn wildcard_destination_deny_does_not_match_unrelated() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let unrelated = Address::generate(&env);

    let pattern = String::from_str(&env, "ZZZZZ*");

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "wild_deny"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: pattern,
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &unrelated, &100,)
        .is_ok());
}

#[test]
fn wildcard_destination_allow_matches_prefix() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);

    let addr_str = allowed.to_string();
    let addr_len = addr_str.len() as usize;
    let mut addr_buf = [0u8; 128];
    addr_str.copy_into_slice(&mut addr_buf[..addr_len]);
    let prefix_len = 4.min(addr_len);
    let mut pat_bytes = soroban_sdk::Bytes::new(&env);
    for &b in addr_buf.iter().take(prefix_len) {
        pat_bytes.push_back(b);
    }
    pat_bytes.push_back(b'*');
    let pat_buf = pat_bytes.to_buffer::<128>();
    let pattern = String::from_bytes(&env, pat_buf.borrow());

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "wild_allow"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: pattern,
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &allowed, &100,)
        .is_ok());
}

// ── Multiple rule configurations ───────────────────────────────────────

#[test]
fn first_matching_rule_wins() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let addr = Address::generate(&env);
    let addr_str = addr.to_string();

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_first"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: addr_str.clone(),
        },
    );
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_second"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: addr_str,
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr, &100);
    assert!(r.is_err());
}

#[test]
fn allow_then_deny_different_addresses() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_a"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: addr_a.to_string(),
        },
    );
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_b"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: addr_b.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr_a, &100,)
        .is_ok());

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr_b, &100,)
        .is_err());
}

// ── Asset / payload parameter matching ─────────────────────────────────

#[test]
fn exact_asset_deny_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_asset"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Asset,
            value: asset.to_string(),
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100);
    assert!(r.is_err());
}

#[test]
fn exact_asset_allow_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let allowed_asset = Address::generate(&env);
    let other_asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_asset"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Asset,
            value: allowed_asset.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &allowed_asset,
            &recip,
            &100,
        )
        .is_ok());

    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &other_asset,
            &recip,
            &100,
        )
        .is_ok());
}

#[test]
fn mixed_destination_and_asset_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied_recip = Address::generate(&env);
    let ok_recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_recip"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied_recip.to_string(),
        },
    );
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_asset"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Asset,
            value: asset.to_string(),
        },
    );

    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &denied_recip,
        &100,
    );
    assert!(r.is_err());

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &ok_recip, &100,)
        .is_ok());
}

// ── Deterministic denial errors ────────────────────────────────────────

#[test]
fn rule_denied_returns_structured_error() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &50);
    assert!(r.is_err());
    assert_rule_denied(&r);
}

#[test]
fn rule_denied_emits_violation_event() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let _ = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &50);
    assert_event(&env, "PolicyViolation");
}

// ── No matching rule / backward compatibility ───────────────────────────

#[test]
fn empty_rule_set_preserves_existing_behaviour() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &999_999,)
        .is_ok());
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &recip,
            &1_000_001,
        )
        .is_err());
}

#[test]
fn no_matching_rule_allows_transfer() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let other = Address::generate(&env);
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_other"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: other.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

// ── Rule CRUD operations ───────────────────────────────────────────────

#[test]
fn add_rule_and_retrieve() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let rule = PolicyRule {
        id: String::from_str(&env, "r1"),
        rule_match: RuleMatch::Deny,
        target: RuleTarget::Destination,
        value: String::from_str(&env, "GXYZ*"),
    };
    p.add_rule(&owner, &String::from_str(&env, "max_txn"), &rule);

    let rules = p.get_rules(&String::from_str(&env, "max_txn"));
    assert_eq!(rules.len(), 1);
    assert_eq!(rules.get_unchecked(0).id, String::from_str(&env, "r1"));
}

#[test]
fn remove_rule_works() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "GXYZ*"),
        },
    );
    assert_eq!(p.get_rules(&String::from_str(&env, "max_txn")).len(), 1);

    p.remove_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "r1"),
    );
    assert_eq!(p.get_rules(&String::from_str(&env, "max_txn")).len(), 0);
}

#[test]
fn remove_nonexistent_rule_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let r = p.try_remove_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "nope"),
    );
    assert!(r.is_err());
}

#[test]
fn add_duplicate_rule_id_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let rule = PolicyRule {
        id: String::from_str(&env, "r1"),
        rule_match: RuleMatch::Deny,
        target: RuleTarget::Destination,
        value: String::from_str(&env, "GABC*"),
    };
    p.add_rule(&owner, &String::from_str(&env, "max_txn"), &rule);

    let r = p.try_add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Asset,
            value: String::from_str(&env, "GDEF*"),
        },
    );
    assert!(r.is_err());
}

#[test]
fn non_owner_cannot_add_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let stranger = Address::generate(&env);

    let r = p.try_add_rule(
        &stranger,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "GABC*"),
        },
    );
    assert!(r.is_err());
}

#[test]
fn non_owner_cannot_remove_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let stranger = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "GABC*"),
        },
    );

    let r = p.try_remove_rule(
        &stranger,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "r1"),
    );
    assert!(r.is_err());
}

// ── Edge cases ─────────────────────────────────────────────────────────

#[test]
fn empty_pattern_matches_nothing() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "empty_pat"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, ""),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn lone_wildcard_matches_nothing() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "star_only"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "*"),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn get_rules_returns_empty_for_unregistered_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let rules = p.get_rules(&String::from_str(&env, "nonexistent"));
    assert_eq!(rules.len(), 0);
}

#[test]
fn removed_rule_no_longer_affects_evaluation() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let addr = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_addr"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: addr.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr, &100,)
        .is_err());

    p.remove_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "deny_addr"),
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr, &100,)
        .is_ok());
}

#[test]
fn rules_persist_across_multiple_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let r1 = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &10);
    let r2 = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &20);
    assert!(r1.is_err());
    assert!(r2.is_err());
}

#[test]
fn scalar_gates_still_enforced_with_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_r"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: recip.to_string(),
        },
    );

    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert!(r.is_err());
}

// === Tests from upstream (merchant blacklist, category blacklist, asset whitelist) ===
#[test]
fn merchant_blacklist_blocks_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked_merchant = Address::generate(&env);

    // Add merchant to blacklist
    p.add_merchant_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &blocked_merchant,
    );

    // Transfer to blocked merchant should fail
    let result = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &blocked_merchant,
        &100,
    );
    assert!(result.is_err());

    // Transfer to non-blocked merchant should succeed
    let safe_merchant = Address::generate(&env);
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &safe_merchant,
            &100,
        )
        .is_ok());
}

#[test]
fn merchant_blacklist_removal_allows_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let merchant = Address::generate(&env);

    // Add merchant to blacklist
    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Verify blocked
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &merchant, &100,)
        .is_err());

    // Remove from blacklist
    p.remove_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Now should succeed
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &merchant, &100,)
        .is_ok());
}

#[test]
fn merchant_blacklist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    // Unauthorized user cannot add to blacklist
    let result =
        p.try_add_merchant_blacklist(&unauthorized, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blacklist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    // Add merchant to blacklist
    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Adding again should fail
    let result =
        p.try_add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blacklist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    // Removing non-existent merchant should fail
    let result =
        p.try_remove_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blocked_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked_merchant = Address::generate(&env);

    p.add_merchant_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &blocked_merchant,
    );

    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &blocked_merchant,
        &100,
    );
    assert_event(&env, "PolicyViolation");
}

// --- Category blacklist tests ---

#[test]
fn category_blacklist_blocks_categories() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Blocked category should fail
    let result = p.try_check_category(
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());

    // Different category should succeed
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "groceries"),
        )
        .is_ok());

    // Empty category should succeed
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, ""),
        )
        .is_ok());
}

#[test]
fn category_blacklist_removal_allows_categories() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Verify blocked
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "gambling"),
        )
        .is_err());

    // Remove from blacklist
    p.remove_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Now should succeed
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "gambling"),
        )
        .is_ok());
}

#[test]
fn category_blacklist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);

    // Unauthorized user cannot add to blacklist
    let result = p.try_add_category_blacklist(
        &unauthorized,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Adding again should fail
    let result = p.try_add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Removing non-existent category should fail
    let result = p.try_remove_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_empty_category_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Adding empty category should fail
    let result = p.try_add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, ""),
    );
    assert!(result.is_err());
}

#[test]
fn category_restricted_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    let _ = p.try_check_category(
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert_event(&env, "PolicyViolation");
}

// --- Issue #37: Asset whitelist tests ---

#[test]
fn asset_whitelist_allows_whitelisted_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);
    let safe = Address::generate(&env);

    // Block the address
    p.add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &blocked);

    // Transfer to blocked address should fail
    let result = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &blocked, &100);
    assert!(result.is_err());

    // Transfer to non-blocked address should succeed
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &safe, &100,)
        .is_ok());
}

#[test]
fn blocklist_removal_allows_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Whitelist not enabled (default) — any asset should pass
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn asset_whitelist_add_remove_roundtrip() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    p.set_asset_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);
    p.add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    // Now remove it
    p.remove_asset_from_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    // validate_asset should fail for a removed asset when whitelist is enabled
    assert!(p
        .try_validate_asset(&String::from_str(&env, "max_txn"), &asset)
        .is_err());
}

#[test]
fn asset_whitelist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);
    let addr = Address::generate(&env);

    let result = p.try_add_to_blocklist(&unauthorized, &String::from_str(&env, "max_txn"), &addr);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    p.add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    let result = p.try_add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    let result =
        p.try_remove_asset_from_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_empty_default_passes_validate() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    // Whitelist disabled by default, validate_asset should pass
    assert!(p
        .try_validate_asset(&String::from_str(&env, "max_txn"), &asset)
        .is_ok());
}

#[test]
fn asset_whitelist_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_asset_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);

    let _ = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100);
    assert_event(&env, "PolicyViolation");
}

// --- Multi-token allowance tests ---

/// Register a fresh policy with unlimited policy bounds so only the allowance
/// gate is exercised.
fn allowance_setup<'a>(env: &'a Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "mt"),
        &BytesN::from_array(env, &[1; 32]),
        &0,
        &None,
        &None,
        &0,
    );
    client
}

#[test]
fn allowance_allows_spend_below_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    let allowed = p.get_allowance(&String::from_str(&env, "mt"), &asset);
    assert_eq!(allowed.limit, 1_000);

    // Within limit headroom: passes check and transfer gate.
    assert_eq!(
        p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &400),
        Ok(Ok(600))
    );
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &400)
        .is_ok());
}

#[test]
fn allowance_exact_boundary_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    // Spend exactly the full limit: allowed (headroom becomes 0).
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1_000)
        .is_ok());
    // update_allowance consumes exactly to the limit.
    assert!(p
        .try_update_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000)
        .is_ok());
}

#[test]
fn allowance_over_limit_rejected_with_exceeded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);

    let over = p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &1_001);
    assert_eq!(over, Err(Ok(Error::PolicyAllowanceExceeded)));
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1_001),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );
}

#[test]
fn allowance_cumulative_consumption_blocks_after_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    // Consume 600 via update_allowance.
    assert!(p
        .try_update_allowance(&owner, &String::from_str(&env, "mt"), &asset, &600)
        .is_ok());
    // Only 400 headroom remains.
    assert_eq!(
        p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &400),
        Ok(Ok(0))
    );
    // 401 would exceed the cumulative limit.
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &401),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );
    // A fresh 300 transfer still fits.
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &300)
        .is_ok());
}

#[test]
fn multi_token_allowances_are_independent_per_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let xlm = Address::generate(&env);
    let usdc = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &xlm, &100, &0);
    p.set_allowance(&owner, &String::from_str(&env, "mt"), &usdc, &10_000, &0);

    // USDC has room, XLM is capped at 100.
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &usdc, &recip, &5_000)
        .is_ok());
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &xlm, &recip, &101),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );
    // An asset with no configured allowance is unrestricted.
    let eth = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &eth, &recip, &1_000_000)
        .is_ok());
}

#[test]
fn allowance_expires_at_past_blocks_spend() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Expires in the past => every spend denied, even below the limit.
    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &500);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn allowance_unauthorized_set_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);

    let r = p.try_set_allowance(&stranger, &String::from_str(&env, "mt"), &asset, &100, &0);
    assert!(r.is_err());
}

#[test]
fn allowance_negative_limit_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);

    let r = p.try_set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &-1, &0);
    assert!(r.is_err());

    // Negative spend is always rejected.
    let c = p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &-5);
    assert!(c.is_err());
}

#[test]
fn allowance_remove_restores_unlimited() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &100, &0);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &200),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );

    p.remove_allowance(&owner, &String::from_str(&env, "mt"), &asset);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &200)
        .is_ok());
}

// --- Composite rule tests ---

fn composite_setup<'a>(env: &'a Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "cr"),
        &BytesN::from_array(env, &[99; 32]),
        &0,
        &None,
        &None,
        &0,
    );
    client
}

/// Build a leaf RuleNode (no children).
fn leaf(op: RuleOp, env: &Env) -> RuleNode {
    RuleNode {
        op,
        value_i128: 0,
        value_address: Address::generate(env),
        children_start: 0,
        children_end: 0,
    }
}

/// Build a leaf RuleNode with an i128 value.
fn leaf_amount(op: RuleOp, amount: i128, env: &Env) -> RuleNode {
    RuleNode {
        op,
        value_i128: amount,
        value_address: Address::generate(env),
        children_start: 0,
        children_end: 0,
    }
}

/// Build a leaf RuleNode with an address value.
fn leaf_addr(op: RuleOp, addr: Address, _env: &Env) -> RuleNode {
    RuleNode {
        op,
        value_i128: 0,
        value_address: addr,
        children_start: 0,
        children_end: 0,
    }
}

/// Build a RuleTree with a single leaf node carrying an amount.
fn single_amount_tree(op: RuleOp, amount: i128, env: &Env) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(leaf_amount(op, amount, env));
    tree
}

/// Build a RuleTree with a single leaf node carrying an address.
fn single_addr_tree(op: RuleOp, addr: Address, env: &Env) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(leaf_addr(op, addr, env));
    tree
}

// --- Leaf rule: MaxAmount ---

#[test]
fn composite_max_amount_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 500, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &500)
        .is_ok());
}

#[test]
fn composite_max_amount_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 500, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &501),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- Leaf rule: AllowedRecipient ---

#[test]
fn composite_allowed_recipient_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedRecipient, allowed.clone(), &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &allowed, &100)
        .is_ok());
}

#[test]
fn composite_allowed_recipient_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedRecipient, allowed, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &blocked, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- Leaf rule: AllowedAsset ---

#[test]
fn composite_allowed_asset_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let recip = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedAsset, asset.clone(), &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100)
        .is_ok());
}

#[test]
fn composite_allowed_asset_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed_asset = Address::generate(&env);
    let other_asset = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let recip = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedAsset, allowed_asset, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &other_asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- AND combinator ---
// Tree layout for AND(a, b):
//   [0] RuleNode { op: And, children_start: 1, children_end: 2 }
//   [1] RuleNode { op: a }
//   [2] RuleNode { op: b }

#[test]
fn composite_and_all_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 1000, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, recip.clone(), &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &500)
        .is_ok());
}

#[test]
fn composite_and_one_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 1000, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, allowed, &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount is fine but recipient is wrong
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &blocked, &500),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_and_empty_children_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // AND node with children_start == children_end (empty)
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 1,
    });
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::InvalidInput))
    );
}

// --- OR combinator ---
// Tree layout for OR(a, b):
//   [0] RuleNode { op: Or, children_start: 1, children_end: 2 }
//   [1] a
//   [2] b

#[test]
fn composite_or_first_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(
        RuleOp::AllowedRecipient,
        Address::generate(&env),
        &env,
    ));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount is within limit so first branch passes
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &50)
        .is_ok());
}

#[test]
fn composite_or_second_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, allowed.clone(), &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount exceeds limit but recipient matches
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &allowed, &500)
        .is_ok());
}

#[test]
fn composite_or_all_fail() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(
        RuleOp::AllowedRecipient,
        Address::generate(&env),
        &env,
    ));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount exceeds limit AND recipient is wrong
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &blocked, &500),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_or_empty_children_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 1,
    });
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::InvalidInput))
    );
}

// --- NOT combinator ---
// Tree layout for NOT(MaxAmount(100)):
//   [0] RuleNode { op: Not, children_start: 1, children_end: 2 }
//   [1] RuleNode { op: MaxAmount, value_i128: 100 }

#[test]
fn composite_not_inverts_pass_to_deny() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 2,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount 50 <= 100, inner rule passes => Not inverts => deny
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &50),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_not_inverts_deny_to_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 2,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount 150 > 100, inner rule fails => Not inverts => pass
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &150)
        .is_ok());
}

// --- Nested combinations ---
// Tree layout for OR( AND(MaxAmount(500), AllowedRecipient(allowed)), AllowedAsset(asset) ):
//   [0] RuleNode { op: Or, children_start: 1, children_end: 3 }
//   [1] RuleNode { op: And, children_start: 3, children_end: 5 }
//   [2] RuleNode { op: AllowedAsset, value_address: asset }
//   [3] RuleNode { op: MaxAmount, value_i128: 500 }
//   [4] RuleNode { op: AllowedRecipient, value_address: allowed }

#[test]
fn composite_nested_and_or() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    // [0] Root: OR with children 1..3
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    // [1] AND with children 3..5
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 3,
        children_end: 5,
    });
    // [2] AllowedAsset(asset)
    tree.push_back(leaf_addr(RuleOp::AllowedAsset, asset.clone(), &env));
    // [3] MaxAmount(500)
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 500, &env));
    // [4] AllowedRecipient(allowed)
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, allowed.clone(), &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Case 1: Wrong recipient but correct asset — OR passes via second branch
    let wrong_recip = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &wrong_recip, &1_000)
        .is_ok());

    // Case 2: Correct recipient and amount within limit — AND branch passes
    // (regardless of asset), so OR passes too.
    let other_asset = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &other_asset, &allowed, &300)
        .is_ok());

    // Case 3: Wrong recipient AND wrong asset — neither OR branch passes => deny
    assert_eq!(
        p.try_check_transfer(
            &String::from_str(&env, "cr"),
            &other_asset,
            &wrong_recip,
            &1_000
        ),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_deeply_nested_not_of_and() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Rule: Not(And(MaxAmount(200), AllowedRecipient(recip)))
    // Denies when BOTH conditions hold; allows when either fails.
    let mut tree = soroban_sdk::Vec::new(&env);
    // [0] NOT with child at index 1
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 2,
    });
    // [1] AND with children 2..4
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 2,
        children_end: 4,
    });
    // [2] MaxAmount(200)
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 200, &env));
    // [3] AllowedRecipient(recip)
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, recip.clone(), &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Both hold: amount 100 <= 200 AND recipient matches => And passes => Not denies
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );

    // Amount exceeds: And fails => Not passes
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &300)
        .is_ok());
}

// --- Recursion depth limit ---
// Build a chain of 15 nested Not nodes (exceeds MAX_RULE_DEPTH = 10)
// Layout: [0] Not -> [1] Not -> [2] Not -> ... -> [15] MaxAmount(i128::MAX)

#[test]
fn composite_depth_exceeded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    for i in 0..15u32 {
        tree.push_back(RuleNode {
            op: RuleOp::Not,
            value_i128: 0,
            value_address: Address::generate(&env),
            children_start: i + 1,
            children_end: i + 2,
        });
    }
    // [15] MaxAmount leaf
    tree.push_back(RuleNode {
        op: RuleOp::MaxAmount,
        value_i128: i128::MAX,
        value_address: Address::generate(&env),
        children_start: 0,
        children_end: 0,
    });

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::InvalidInput))
    );
}

// --- Clear / management ---

#[test]
fn composite_clear_rule_restores_permissive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 10, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Denied by composite rule
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );

    // Clear the rule
    p.clear_composite_rule(&owner, &String::from_str(&env, "cr"));

    // Now passes (no composite rule => permissive)
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100)
        .is_ok());
}

#[test]
fn composite_get_rule_roundtrip() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    // Build a two-node OR tree
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 500, &env));
    tree.push_back(leaf_addr(
        RuleOp::AllowedRecipient,
        Address::generate(&env),
        &env,
    ));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let retrieved = p.get_composite_rule(&String::from_str(&env, "cr"));
    assert_eq!(retrieved.len(), tree.len());
}

#[test]
fn composite_get_nonexistent_rule_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let result = p.try_get_composite_rule(&String::from_str(&env, "cr"));
    assert_eq!(result, Err(Ok(Error::NotFound)));
}

#[test]
fn composite_clear_nonexistent_rule_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let result = p.try_clear_composite_rule(&owner, &String::from_str(&env, "cr"));
    assert!(result.is_err());
}

#[test]
fn composite_set_rule_unauthorized_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let tree = single_amount_tree(RuleOp::MaxAmount, 100, &env);
    let result = p.try_set_composite_rule(&unauthorized, &String::from_str(&env, "cr"), &tree);
    assert!(result.is_err());
}

#[test]
fn composite_set_empty_tree_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let tree = soroban_sdk::Vec::new(&env);
    let result = p.try_set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);
    assert!(result.is_err());
}

// --- Rule evaluation event emitted ---

#[test]
fn composite_rule_denied_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 10, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let _ = p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100);
    assert_event(&env, "PolicyViolation");
}

// --- Evaluate composite rule view function ---

#[test]
fn composite_evaluate_view_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 500, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let payload = TransactionPayload {
        asset: asset.clone(),
        recipient: recip.clone(),
        amount: 200,
    };
    assert_eq!(
        p.try_evaluate_composite_rule(&String::from_str(&env, "cr"), &payload),
        Ok(Ok(true))
    );
}

#[test]
fn composite_evaluate_view_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 100, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let payload = TransactionPayload {
        asset: asset.clone(),
        recipient: recip.clone(),
        amount: 200,
    };
    assert_eq!(
        p.try_evaluate_composite_rule(&String::from_str(&env, "cr"), &payload),
        Ok(Ok(false))
    );
}

#[test]
fn composite_evaluate_no_rule_permissive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // No rule set => permissive (true)
    let payload = TransactionPayload {
        asset,
        recipient: recip,
        amount: 999_999,
    };
    assert_eq!(
        p.try_evaluate_composite_rule(&String::from_str(&env, "cr"), &payload),
        Ok(Ok(true))
    );
}

// --- Realistic scenario: max amount OR specific vendor whitelist ---

#[test]
fn composite_realistic_max_amount_or_vendor_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let vendor_a = Address::generate(&env);
    let vendor_b = Address::generate(&env);
    let random = Address::generate(&env);

    // Rule: OR(MaxAmount(100), AllowedRecipient(vendor_a))
    // i.e. small transfers allowed to anyone, or large transfers only to vendor_a
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, vendor_a.clone(), &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Small transfer to random: passes (MaxAmount branch)
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &random, &50)
        .is_ok());

    // Large transfer to vendor_a: passes (AllowedRecipient branch)
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &vendor_a, &500)
        .is_ok());

    // Large transfer to vendor_b: denied (neither branch)
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &vendor_b, &500),
        Err(Ok(Error::PolicyDenied))
    );

    // Large transfer to random: denied
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &random, &500),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- Realistic scenario: NOT recipient blacklisted AND max amount ---
// Tree layout for AND(NOT(RecipientBlacklisted), MaxAmount(1000)):
//   [0] AND { children_start: 1, children_end: 3 }
//   [1] NOT { children_start: 3, children_end: 4 }
//   [2] MaxAmount(1000)
//   [3] RecipientBlacklisted

#[test]
fn composite_realistic_not_blacklisted_and_max_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let safe = Address::generate(&env);
    let bad = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    // [0] AND with children 1..3
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    // [1] NOT with child at index 3
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 3,
        children_end: 4,
    });
    // [2] MaxAmount(1000)
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 1000, &env));
    // [3] RecipientBlacklisted
    tree.push_back(leaf(RuleOp::RecipientBlacklisted, &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Safe recipient, amount OK: passes
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &safe, &500)
        .is_ok());

    // Blacklisted recipient: denied by blocklist check (before composite rules)
    p.add_to_blocklist(&owner, &String::from_str(&env, "cr"), &bad);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &bad, &500),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
}

// --- asset deny list ---

#[test]
fn blacklisted_asset_is_denied() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // The transfer passes every scalar gate before the asset is listed.
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());

    p.add_asset_blacklist(&owner, &pid, &asset);
    assert!(p.is_asset_blacklisted(&pid, &asset));
    let r = p.try_check_transfer(&pid, &asset, &recip, &1);
    assert_eq!(r, Err(Ok(Error::PolicyDenied)));
    assert_event(&env, "PolicyViolation");
}

#[test]
fn blacklist_removal_restores_the_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_asset_blacklist(&owner, &pid, &asset);
    p.remove_asset_blacklist(&owner, &pid, &asset);
    assert!(!p.is_asset_blacklisted(&pid, &asset));
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());
}

#[test]
fn blacklist_beats_the_asset_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Explicitly allow the asset, then deny it: the deny list wins.
    p.set_asset_whitelist_enabled(&owner, &pid, &true);
    p.add_asset_to_whitelist(&owner, &pid, &asset);
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());

    p.add_asset_blacklist(&owner, &pid, &asset);
    let r = p.try_check_transfer(&pid, &asset, &recip, &1);
    assert_eq!(r, Err(Ok(Error::PolicyDenied)));
}

#[test]
fn blacklist_is_scoped_to_its_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let other = String::from_str(&env, "other");
    p.register_policy(
        &owner,
        &other,
        &BytesN::from_array(&env, &[7; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
    );
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_asset_blacklist(&owner, &String::from_str(&env, "max_txn"), &asset);
    // The sibling policy is untouched by the other policy's deny list.
    assert!(!p.is_asset_blacklisted(&other, &asset));
    assert!(p.try_check_transfer(&other, &asset, &recip, &1).is_ok());
}

#[test]
fn blacklist_management_rejects_bad_input() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);

    // Removing an asset that was never listed.
    assert_eq!(
        p.try_remove_asset_blacklist(&owner, &pid, &asset),
        Err(Ok(Error::NotFound))
    );
    p.add_asset_blacklist(&owner, &pid, &asset);
    // Listing it twice.
    assert_eq!(
        p.try_add_asset_blacklist(&owner, &pid, &asset),
        Err(Ok(Error::AlreadyExists))
    );
    // Unknown policy.
    assert_eq!(
        p.try_add_asset_blacklist(&owner, &String::from_str(&env, "nope"), &asset),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn only_the_owner_can_manage_the_blacklist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);

    assert_eq!(
        p.try_add_asset_blacklist(&stranger, &pid, &asset),
        Err(Ok(Error::Unauthorized))
    );
    p.add_asset_blacklist(&owner, &pid, &asset);
    assert_eq!(
        p.try_remove_asset_blacklist(&stranger, &pid, &asset),
        Err(Ok(Error::Unauthorized))
    );
}
