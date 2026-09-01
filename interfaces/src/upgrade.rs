//! Registry-gated contract upgrades.
//!
//! Soroban lets a contract replace its own code with
//! [`soroban_sdk::deploy::Deployer::update_current_contract_wasm`]. On its own
//! that is an unconditional power: whoever the contract accepts as an admin can
//! point it at *any* uploaded Wasm. Astroid's upgrade strategy (PRD Doc 7
//! §Upgrade Strategy) instead makes the registry the single source of truth for
//! which implementations exist, so this module routes every member contract's
//! upgrade through it:
//!
//! ```text
//! caller ──auth──▶ member contract ──registry.is_wasm_approved(kind, hash)──▶ registry
//!                        │                                       approved? │
//!                        └──── update_current_contract_wasm(hash) ◀─────────┘
//! ```
//!
//! Both gates must pass: the caller must be the contract's recorded upgrade
//! admin, and the new Wasm hash must be approved for that [`ModuleKind`] in the
//! registry. Anything else fails with [`Error::Unauthorized`] and the contract
//! keeps running its current code.
//!
//! The helpers live here rather than in `astroid-shared` because they need a
//! generated cross-contract client, and here rather than in each contract
//! because every member contract must enforce the identical rule.

use astroid_shared::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::{contractclient, contracttype, symbol_short, Address, BytesN, Env};

/// The slice of the registry an upgrading contract needs: whether a Wasm hash is
/// approved for a module kind.
///
/// Declared here as its own client rather than folded into `RegistryInterface`
/// so the registry keeps exposing `is_wasm_approved` as a plain entrypoint and
/// nothing else has to change to be callable.
#[contractclient(name = "UpgradeRegistryClient")]
pub trait UpgradeRegistryInterface {
    /// Whether `wasm_hash` is an approved implementation for `kind`.
    fn is_wasm_approved(env: Env, kind: ModuleKind, wasm_hash: BytesN<32>) -> bool;
}

/// Instance-storage key for the upgrade authority. Namespaced under its own
/// type so it can never collide with a contract's own `DataKey`.
#[contracttype]
#[derive(Clone)]
enum UpgradeKey {
    Authority,
}

/// Who may upgrade a contract, and which registry authorizes the new code.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAuthority {
    /// The only address allowed to request an upgrade.
    pub admin: Address,
    /// Registry contract consulted for the approved implementations.
    pub registry: Address,
}

/// Record (or rotate) the upgrade authority.
///
/// The first call bootstraps it and should be made by the deployer in the same
/// transaction as the contract's own `initialize`, exactly like the other
/// first-come initializers in this workspace. Afterwards only the current admin
/// may rotate it, and the call is authenticated either way.
pub fn set_authority(
    env: &Env,
    caller: &Address,
    admin: &Address,
    registry: &Address,
) -> Result<(), Error> {
    caller.require_auth();
    if let Some(current) = stored(env) {
        if &current.admin != caller {
            return Err(Error::Unauthorized);
        }
    }
    env.storage().instance().set(
        &UpgradeKey::Authority,
        &UpgradeAuthority {
            admin: admin.clone(),
            registry: registry.clone(),
        },
    );
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    env.events().publish(
        (symbol_short!("upgrade"), symbol_short!("auth")),
        (admin.clone(), registry.clone()),
    );
    Ok(())
}

/// Read the recorded upgrade authority.
pub fn get_authority(env: &Env) -> Result<UpgradeAuthority, Error> {
    stored(env).ok_or(Error::NotInitialized)
}

/// Authorize an upgrade without performing it: authenticate `caller` as the
/// upgrade admin and confirm `wasm_hash` is approved for `kind` in the registry.
///
/// Exposed on its own so an upgrade can be validated (by a keeper, a dry run or
/// a test) without swapping any code.
pub fn check(
    env: &Env,
    caller: &Address,
    kind: ModuleKind,
    wasm_hash: &BytesN<32>,
) -> Result<(), Error> {
    caller.require_auth();
    let authority = get_authority(env)?;
    if &authority.admin != caller {
        return Err(Error::Unauthorized);
    }
    let registry = UpgradeRegistryClient::new(env, &authority.registry);
    match registry.try_is_wasm_approved(&kind, wasm_hash) {
        Ok(Ok(true)) => Ok(()),
        // The registry answered, and the answer is no.
        Ok(Ok(false)) => Err(Error::Unauthorized),
        // The registry returned something that is not a bool, rejected the
        // call (e.g. it is frozen), or failed at the host level. `is_wasm_approved`
        // is infallible on the registry side, so any of these means we could not
        // establish approval — fail closed rather than upgrade.
        Ok(Err(_)) | Err(_) => Err(Error::Unauthorized),
    }
}

/// Authorize and then perform the upgrade: on success the contract's code is
/// replaced with `wasm_hash`.
///
/// [`check`] runs first, so an unauthorized caller or an unapproved hash aborts
/// before `update_current_contract_wasm` is ever reached. The new code takes
/// effect after the current invocation completes.
pub fn perform(
    env: &Env,
    caller: &Address,
    kind: ModuleKind,
    wasm_hash: BytesN<32>,
) -> Result<(), Error> {
    check(env, caller, kind, &wasm_hash)?;
    env.deployer()
        .update_current_contract_wasm(wasm_hash.clone());
    env.events().publish(
        (symbol_short!("upgrade"), symbol_short!("applied")),
        (kind, wasm_hash),
    );
    Ok(())
}

fn stored(env: &Env) -> Option<UpgradeAuthority> {
    env.storage().instance().get(&UpgradeKey::Authority)
}
