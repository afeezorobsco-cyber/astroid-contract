#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Registry Contract
//!
//! The backbone of the protocol and its single source of truth. The registry
//! records, per organization:
//! - the **owner** of the organization,
//! - the **module address** for each [`ModuleKind`] (wallet, treasury, policy…),
//!
//! and, globally, a **version → address** table used by the upgrade strategy so
//! new contract versions (e.g. Wallet v1 → v2 → v3) can be introduced without
//! breaking consumers (PRD Doc 7 §Upgrade Strategy).
//!
//! Security model (PRD Doc 10): validate caller → ownership → inputs →
//! permissions → fail safely → emit events. All mutating calls are admin- or
//! owner-gated and require Soroban auth.
//!
//! ## Permission delegation
//!
//! Requiring the root owner's key for every registry edit does not survive
//! contact with a real organization: the people who rotate a policy contract
//! are usually not the people who hold ultimate ownership, and handing them the
//! root key to do it defeats the point of having one. The registry therefore
//! records a [`RegistryRole`] per `(organization, account)` and checks it on the
//! org-scoped modifications, so an owner can delegate narrow administrative
//! powers to sub-accounts or secondary operational keys without transferring
//! ownership:
//!
//! | Role               | May register/remove modules of kind                |
//! |--------------------|----------------------------------------------------|
//! | `Owner`            | any kind (a delegated co-owner for module records) |
//! | `ModuleUpgrader`   | any kind (repointing modules at new versions)      |
//! | `PolicyManager`    | `Policy`                                           |
//! | `TreasuryOperator` | `Treasury`, `Budget`, `Escrow`                     |
//!
//! Delegation is deliberately bounded. Root actions — transferring ownership,
//! the emergency freeze, and administering roles themselves — stay with the
//! recorded org owner and the protocol admin, so no grant can be used to
//! escalate into ownership or to widen its own reach.

use astroid_interfaces::RegistryInterface;
use astroid_shared::constants::{PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::types::ModuleKind;
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String,
};

/// Storage keys. `Admin` lives in instance storage; everything else is keyed
/// per organization/module in persistent storage.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Protocol admin (instance).
    Admin,
    /// Organization owner: org slug -> owner address.
    Org(String),
    /// Module address: (org slug, kind) -> contract address.
    Module(String, ModuleKind),
    /// Module deprecation flag: (org slug, kind) -> bool. When set, the routing
    /// surface (`lookup`) rejects new interactions with [`Error::ModuleDeprecated`]
    /// while the raw address stays readable for legacy migrations.
    ModuleDeprecated(String, ModuleKind),
    /// Delegated role: (org slug, account) -> RegistryRole.
    OrgRole(String, Address),
    /// Version table: (kind, version) -> contract address (global upgrade map).
    Version(ModuleKind, u32),
    /// Latest known version number for a kind.
    LatestVersion(ModuleKind),
    /// Emergency freeze status (instance).
    Frozen,
    /// Approved WASM hashes: (kind, hash) -> bool.
    ApprovedWasm(ModuleKind, BytesN<32>),
}

/// A delegated administrative role over one organization's registry records.
///
/// One role per account keeps the ledger footprint to a single small entry per
/// delegation. Roles are capability-scoped rather than ranked: `PolicyManager`
/// is not "less" than `TreasuryOperator`, it simply reaches different module
/// kinds. Discriminants are part of the public ABI and MUST NOT be reordered or
/// reused once released.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRole {
    /// Delegated co-owner of the organization's module records. Reaches every
    /// module kind, but not the root actions (ownership transfer, freeze, role
    /// administration), which stay with the recorded owner.
    Owner = 0,
    /// May manage the organization's `Policy` module registration.
    PolicyManager = 1,
    /// May manage the organization's `Treasury`, `Budget` and `Escrow` module
    /// registrations — the value-custody side of the protocol.
    TreasuryOperator = 2,
    /// May repoint any of the organization's modules, which is what rolling a
    /// module forward to a new implementation version amounts to.
    ModuleUpgrader = 3,
}

impl RegistryRole {
    /// Whether this role may register or remove the module of `kind` for the
    /// organization it was granted on.
    pub fn may_manage(self, kind: ModuleKind) -> bool {
        match self {
            RegistryRole::Owner | RegistryRole::ModuleUpgrader => true,
            RegistryRole::PolicyManager => matches!(kind, ModuleKind::Policy),
            RegistryRole::TreasuryOperator => matches!(
                kind,
                ModuleKind::Treasury | ModuleKind::Budget | ModuleKind::Escrow
            ),
        }
    }
}

#[contract]
pub struct RegistryContract;

// ---------------------------------------------------------------------------
// Administration & registration (inherent surface).
// ---------------------------------------------------------------------------
#[contractimpl]
impl RegistryContract {
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
    /// `wasm_hash` must be approved for [`ModuleKind::Organization`] in the registry. Any
    /// other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Organization,
            wasm_hash,
        )
    }
    /// Initialize the registry with its administrator. Callable once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("init")), admin);
        Ok(())
    }

    /// Register an organization and its owner. Admin-gated.
    pub fn register_org(
        env: Env,
        caller: Address,
        org: String,
        owner: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        Self::require_admin(&env, &caller)?;
        let key = DataKey::Org(org.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &owner);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("org"), symbol_short!("register"), org.clone()),
            owner,
        );
        Ok(())
    }

    /// Transfer ownership of an organization. Only the current owner or the
    /// admin may reassign it.
    pub fn set_org_owner(
        env: Env,
        caller: Address,
        org: String,
        new_owner: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        let key = DataKey::Org(org.clone());
        let current: Address = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        if caller != current && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        env.storage().persistent().set(&key, &new_owner);
        Self::bump(&env, &key);
        astroid_shared::events::publish(
            &env,
            ContractEvent::OrgOwnerChanged {
                org: org.clone(),
                new_owner: new_owner.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("org"), symbol_short!("owner"), org.clone()),
            new_owner,
        );
        Ok(())
    }

    /// Register (or update) a module address for an organization. Callable by
    /// the protocol admin, the organization owner, or an account holding a
    /// delegated [`RegistryRole`] that reaches this [`ModuleKind`].
    pub fn register_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &address);
        Self::bump(&env, &key);
        // A (re)registration points at a fresh implementation, so any prior
        // deprecation flag must not carry over and block the new address.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpdated {
                org: org.clone(),
                kind,
                address: address.clone(),
            },
        );
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("register"),
                org.clone(),
                kind,
            ),
            address,
        );
        Ok(())
    }

    /// Mark a registered module as deprecated. Admin-gated. Once flagged,
    /// [`Self::lookup`] rejects new interactions with [`Error::ModuleDeprecated`]
    /// while the raw address remains readable through [`Self::get_module_address`]
    /// so legacy migrations can still reach the old implementation.
    pub fn deprecate_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&mkey) {
            return Err(Error::NotFound);
        }
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        env.storage().persistent().set(&dkey, &true);
        Self::bump(&env, &dkey);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("deprecate")),
            (org, kind),
        );
        Ok(())
    }

    /// Clear a module's deprecation flag, restoring normal routing. Admin-gated.
    pub fn reactivate_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&mkey) {
            return Err(Error::NotFound);
        }
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        env.storage().persistent().set(&dkey, &false);
        Self::bump(&env, &dkey);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("restore")),
            (org, kind),
        );
        Ok(())
    }

    /// Read a module's deprecation status (false when never flagged).
    pub fn is_module_deprecated(env: Env, org: String, kind: ModuleKind) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ModuleDeprecated(org, kind))
            .unwrap_or(false)
    }

    /// Read a registered module address bypassing the deprecation guard.
    /// Intended for legacy migrations and admin tooling that must still reach a
    /// deprecated implementation.
    pub fn get_module_address(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Module(org, kind))
            .ok_or(Error::NotFound)
    }

    /// Remove a module registration. Same gate as `register_module`: admin, org
    /// owner, or a delegated role that reaches this [`ModuleKind`].
    pub fn remove_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let key = DataKey::Module(org.clone(), kind);
        ensure!(env.storage().persistent().has(&key), Error::NotFound);
        env.storage().persistent().remove(&key);
        // Drop the deprecation flag together with the record so a later
        // re-registration starts clean and lookups report NotFound, not
        // ModuleDeprecated, for a removed module.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("remove"),
                org.clone(),
                kind,
            ),
            (),
        );
        Ok(())
    }

    /// Delegate `role` over `org` to `account`, replacing any role it already
    /// held. Only the recorded organization owner or the protocol admin may
    /// grant, so a delegated role can never be used to widen its own reach or
    /// to mint further delegations.
    ///
    /// Granting to the org owner is refused: the owner already reaches every
    /// module kind, so the record would be redundant and could only mislead
    /// anyone reading the delegation list.
    pub fn grant_role(
        env: Env,
        caller: Address,
        org: String,
        account: Address,
        role: RegistryRole,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        let owner = Self::require_root_owner(&env, &caller, &org)?;
        if account == owner {
            return Err(Error::InvalidInput);
        }
        let key = DataKey::OrgRole(org.clone(), account.clone());
        env.storage().persistent().set(&key, &role);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("granted")),
            (org, account, role),
        );
        Ok(())
    }

    /// Revoke whatever role `account` holds over `org`. Only the recorded
    /// organization owner or the protocol admin may revoke.
    ///
    /// Fails with [`Error::NotFound`] when the account holds no delegated role,
    /// so a revocation is never silently a no-op — an owner who believes they
    /// have withdrawn access has actually withdrawn it.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        org: String,
        account: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        Self::require_root_owner(&env, &caller, &org)?;
        let key = DataKey::OrgRole(org.clone(), account.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("revoked")),
            (org, account),
        );
        Ok(())
    }

    /// Read the role `account` holds over `org`, or `None` if it holds none.
    ///
    /// The org owner is reported as [`RegistryRole::Owner`] even though no
    /// record is stored for them, so callers see the effective permission
    /// rather than a storage detail.
    pub fn get_role(env: Env, org: String, account: Address) -> Option<RegistryRole> {
        Self::effective_role(&env, &org, &account)
    }

    /// Whether `account` may register or remove the `kind` module for `org` —
    /// the same question the entrypoint guard asks, exposed for off-chain use.
    pub fn can_manage_module(env: Env, org: String, account: Address, kind: ModuleKind) -> bool {
        if Self::is_admin(&env, &account) {
            return true;
        }
        Self::effective_role(&env, &org, &account)
            .map(|role| role.may_manage(kind))
            .unwrap_or(false)
    }

    /// Record a contract implementation address for a `(kind, version)` pair and
    /// advance the latest-version pointer if newer. Admin-gated; this is what
    /// powers the version-lookup upgrade strategy.
    pub fn register_version(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        version: u32,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        ensure!(version != 0, Error::InvalidInput);
        let vkey = DataKey::Version(kind, version);
        env.storage().persistent().set(&vkey, &address);
        Self::bump(&env, &vkey);

        let lkey = DataKey::LatestVersion(kind);
        let latest: u32 = env.storage().persistent().get(&lkey).unwrap_or(0);
        if version > latest {
            env.storage().persistent().set(&lkey, &version);
            Self::bump(&env, &lkey);
        }
        env.events().publish(
            (
                symbol_short!("version"),
                symbol_short!("register"),
                kind,
                version,
            ),
            address,
        );
        Ok(())
    }

    /// Look up a specific implementation version.
    pub fn get_version(env: Env, kind: ModuleKind, version: u32) -> Result<Address, Error> {
        let key = DataKey::Version(kind, version);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(val)
    }

    /// Look up the latest implementation address for a kind.
    pub fn get_latest(env: Env, kind: ModuleKind) -> Result<Address, Error> {
        let key = DataKey::LatestVersion(kind);
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Self::get_version(env, kind, latest)
    }

    /// Read the recorded owner of an organization.
    pub fn get_org_owner(env: Env, org: String) -> Result<Address, Error> {
        let key = DataKey::Org(org);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(val)
    }

    /// Read the current admin.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Rotate the admin. Only the current admin may do this.
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events().publish(
            (symbol_short!("registry"), symbol_short!("setadmin")),
            new_admin,
        );
        Ok(())
    }

    /// Emergency freeze - only registered org owners can freeze.
    pub fn freeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        ensure!(
            owner == caller || Self::is_admin(&env, &caller),
            Error::Unauthorized
        );
        env.storage().instance().set(&DataKey::Frozen, &true);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: true,
            },
        );
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("frozen")), org);
        Ok(())
    }

    /// Unfreeze - only registered org owners can unfreeze (works even when frozen).
    pub fn unfreeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        // Bypass frozen check - unfreeze must work even when frozen
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        ensure!(
            owner == caller || Self::is_admin(&env, &caller),
            Error::Unauthorized
        );
        env.storage().instance().set(&DataKey::Frozen, &false);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: false,
            },
        );
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("unfrozen")), org);
        Ok(())
    }

    /// Record an approved WASM hash for a specific module kind.
    pub fn add_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedWasm(kind, wasm_hash.clone());
        env.storage().persistent().set(&key, &true);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("approved")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Remove/deprecate a previously approved WASM hash.
    pub fn remove_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedWasm(kind, wasm_hash.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("removed")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Read-only check to see if a WASM hash is approved for a given kind.
    pub fn is_wasm_approved(env: Env, kind: ModuleKind, wasm_hash: BytesN<32>) -> bool {
        let key = DataKey::ApprovedWasm(kind, wasm_hash);
        env.storage().persistent().get(&key).unwrap_or(false)
    }

    // --- internal helpers ---

    fn check_frozen(env: &Env) -> Result<(), Error> {
        ensure!(
            !env.storage()
                .instance()
                .get::<_, bool>(&DataKey::Frozen)
                .unwrap_or(false),
            Error::RegistryFrozen
        );
        Ok(())
    }

    fn is_admin(env: &Env, who: &Address) -> bool {
        match env.storage().instance().get::<_, Address>(&DataKey::Admin) {
            Some(admin) => &admin == who,
            None => false,
        }
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        ensure!(&admin == caller, Error::Unauthorized);
        Ok(())
    }

    /// Require the caller to be the *recorded* organization owner (or the
    /// protocol admin) and return that owner. Used for the root actions that
    /// are deliberately not delegable, so a delegated role can never administer
    /// roles or otherwise escalate.
    fn require_root_owner(env: &Env, caller: &Address, org: &String) -> Result<Address, Error> {
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        if &owner != caller && !Self::is_admin(env, caller) {
            return Err(Error::Unauthorized);
        }
        Ok(owner)
    }

    /// Resolve the role `account` effectively holds over `org`, treating the
    /// recorded owner as an implicit [`RegistryRole::Owner`]. Returns `None`
    /// for an unknown organization, which the callers report as
    /// [`Error::Unauthorized`] — a stranger asking about a non-existent org
    /// learns nothing either way.
    fn effective_role(env: &Env, org: &String, account: &Address) -> Option<RegistryRole> {
        let owner: Option<Address> = env.storage().persistent().get(&DataKey::Org(org.clone()));
        if owner.as_ref() == Some(account) {
            return Some(RegistryRole::Owner);
        }
        env.storage()
            .persistent()
            .get(&DataKey::OrgRole(org.clone(), account.clone()))
    }

    /// Permission guard for the org-scoped module registrations: the protocol
    /// admin, the org owner, or a delegated role that reaches `kind`.
    fn require_module_permission(
        env: &Env,
        caller: &Address,
        org: &String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        if Self::is_admin(env, caller) {
            return Ok(());
        }
        // An unknown organization has no owner and no roles, so it reports
        // NotFound rather than a permission failure.
        if !env.storage().persistent().has(&DataKey::Org(org.clone())) {
            return Err(Error::NotFound);
        }
        match Self::effective_role(env, org, caller) {
            Some(role) if role.may_manage(kind) => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }

    fn bump(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

// ---------------------------------------------------------------------------
// Shared interface implementation. Guarantees the on-chain signatures match the
// generated `RegistryClient` used by other contracts.
// ---------------------------------------------------------------------------
#[contractimpl]
impl RegistryInterface for RegistryContract {
    fn lookup(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        Self::check_frozen(&env)?;
        let key = DataKey::Module(org.clone(), kind);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        // Routing guard: reject new interactions targeting deprecated modules.
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&DataKey::ModuleDeprecated(org, kind))
            .unwrap_or(false)
        {
            return Err(Error::ModuleDeprecated);
        }
        Self::bump(&env, &key);
        Ok(val)
    }

    fn verify_owner(env: Env, org: String, owner: Address) -> Result<bool, Error> {
        Self::check_frozen(&env)?;
        let key = DataKey::Org(org);
        let recorded: Address = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(recorded == owner)
    }
}

#[cfg(test)]
mod test;
