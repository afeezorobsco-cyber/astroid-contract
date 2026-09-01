#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Wallet Contract
//!
//! Programmable, stateful custody wallets for AI agents. The contract is the
//! on-chain custodian: real assets (Stellar Asset Contract tokens) are held at
//! the wallet contract's own address, while per-wallet balances are tracked in
//! internal bookkeeping so an individual wallet can never spend more than it
//! holds.
//!
//! Lifecycle states (PRD Doc 7 §Wallet): `Active`, `Frozen`, `Paused`,
//! `Archived`. Outbound value movement is only permitted from an `Active`
//! wallet; every other state fails safely with a specific error.
//!
//! ## Emergency circuit breaker
//!
//! The per-wallet states above are the owner's tool: they act on one wallet at
//! a time and the owner must be in a position to use them. Compromised agent
//! keys and abnormal on-chain behaviour do not respect that granularity, so the
//! contract also carries a single contract-wide breaker.
//!
//! While tripped, every outbound path — `transfer`, `withdraw` — and the
//! creation of new wallets are refused with [`Error::WalletPaused`]. Everything
//! needed to inspect and recover stays live: all views, `deposit`, and the
//! per-wallet `freeze` / `pause` / `archive` transitions, so an operator can
//! quarantine individual wallets while the breaker holds the line globally.
//!
//! Authority is deliberately asymmetric. A designated guardian can *trip* the
//! breaker, so reacting to an incident is fast and needs only one key. Only the
//! admin can *reset* it — point `admin` at the organization's multisig and
//! resuming operations requires a threshold of signers.
//!
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`, `emergency_pause`,
//! `emergency_unpause`, `set_guardian`.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted`, `WalletPaused`,
//! `WalletUnpaused` (shared schema) plus wallet-scoped state-change events.
//! Access control is role-based (see [`access`]). Every wallet has an owner,
//! who is implicitly [`Role::Admin`], and may delegate a role to any number of
//! other principals so that organization owners, human managers and autonomous
//! agent executors can share a wallet without sharing all of its powers:
//!
//! | Entrypoint                                   | Minimum role |
//! |----------------------------------------------|--------------|
//! | `withdraw`, `pause`, `unpause`, `archive`     | `Admin`      |
//! | `grant_role`, `revoke_role`                   | `Admin`      |
//! | `transfer`                                    | `Agent`      |
//! | `freeze`, `unfreeze`                          | `Agent`, or the contract admin |
//!
//! A caller whose role is below the requirement — including an `Auditor`, who
//! holds no mutating power at all — is rejected with [`Error::Unauthorized`].
//!
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`, `grant_role`, `revoke_role`.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted` (shared schema)
//! plus wallet-scoped state-change and role-administration events.

use crate::access::Role;
use astroid_shared::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::math::{SafeAdd, SafeSub};
use astroid_shared::types::ResourceState;
use astroid_shared::validation::require_positive_amount;
use astroid_shared::{constants, events};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, Symbol,
};

pub mod access;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Emergency/administrative address able to freeze any wallet (instance).
    Admin,
    /// Designated emergency guardian able to trip the breaker (instance).
    Guardian,
    /// Contract-wide emergency pause flag (instance).
    Paused,
    /// Monotonic wallet id counter (instance).
    WalletCount,
    /// Wallet record: id -> WalletData.
    Wallet(u64),
    /// Per-wallet, per-asset balance: (id, asset) -> i128.
    Balance(u64, Address),
}

/// Stored wallet record. `owner` controls the wallet; `state` gates operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletData {
    pub owner: Address,
    pub state: ResourceState,
}

#[contract]
pub struct WalletContract;

/// Unified wallet operation dispatched through the [`WalletContract::dispatch`]
/// entrypoint.
#[contracttype]
#[derive(Clone)]
pub enum WalletAction {
    Transfer(WalletTransferAction),
    Withdraw(WalletWithdrawAction),
    Freeze,
    Unfreeze,
    Pause,
    Unpause,
}

#[contracttype]
#[derive(Clone)]
pub struct WalletTransferAction {
    pub to: Address,
    pub asset: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone)]
pub struct WalletWithdrawAction {
    pub asset: Address,
    pub amount: i128,
}

#[contractimpl]
impl WalletContract {
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
    /// `wasm_hash` must be approved for [`ModuleKind::Wallet`] in the registry. Any
    /// other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Wallet,
            wasm_hash,
        )
    }
    /// Initialize the contract with an emergency admin (may freeze wallets).
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        // The admin is its own guardian until a dedicated one is designated.
        env.storage().instance().set(&DataKey::Guardian, &admin);
        env.storage().instance().set(&DataKey::WalletCount, &0u64);
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Designate the emergency guardian allowed to trip the circuit breaker
    /// (admin only). Set it to a monitoring service or a partner key so an
    /// incident can be contained without waiting on the admin.
    pub fn set_guardian(env: Env, caller: Address, guardian: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Guardian, &guardian);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("guardian")),
            guardian,
        );
        Ok(())
    }

    /// Trip the contract-wide circuit breaker (admin or guardian).
    ///
    /// Freezes every outbound movement and the creation of new wallets at once.
    /// Reads, deposits and the per-wallet recovery transitions stay available.
    pub fn emergency_pause(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_guardian_or_admin(&env, &caller)?;
        if Self::paused(&env) {
            return Err(Error::InvalidState);
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::bump_instance(&env);
        env.events()
            .publish((Symbol::new(&env, "WalletPaused"),), caller);
        Ok(())
    }

    /// Reset the circuit breaker and resume normal operation.
    ///
    /// Admin only: tripping the breaker is a fast, low-privilege reaction, but
    /// releasing it puts funds back in motion and must clear the higher bar.
    pub fn emergency_unpause(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if !Self::paused(&env) {
            return Err(Error::InvalidState);
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_instance(&env);
        env.events()
            .publish((Symbol::new(&env, "WalletUnpaused"),), caller);
        Ok(())
    }

    /// Create a new wallet owned by `owner`. Returns the new wallet id.
    pub fn create_wallet(env: Env, owner: Address) -> Result<u64, Error> {
        Self::when_not_paused(&env)?;
        owner.require_auth();
        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::WalletCount)
            .ok_or(Error::NotInitialized)?;
        count = (count as i128).safe_add(1)? as u64;
        let id = count;
        let data = WalletData {
            owner: owner.clone(),
            state: ResourceState::Active,
        };
        env.storage().persistent().set(&DataKey::Wallet(id), &data);
        Self::bump_wallet(&env, id);
        env.storage().instance().set(&DataKey::WalletCount, &count);
        Self::bump_instance(&env);
        events::wallet_created(&env, id, &owner);
        events::publish(
            &env,
            events::ContractEvent::WalletCreated {
                wallet_id: id,
                owner: owner.clone(),
            },
        );
        Ok(id)
    }

    /// Fund a wallet: pulls `amount` of `asset` from `from` into custody and
    /// credits the wallet's internal balance. Requires `from` authorization.
    pub fn deposit(
        env: Env,
        wallet_id: u64,
        from: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        from.require_auth();
        let wallet = Self::load_wallet(&env, wallet_id)?;
        // Deposits are refused into archived wallets; other states may receive.
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        // Move real tokens into the contract's custody, then credit internally.
        token::TokenClient::new(&env, &asset).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
        Self::credit(&env, wallet_id, &asset, amount)?;
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("deposit")),
            (wallet_id, asset, amount),
        );
        Ok(())
    }

    /// Pay `amount` of `asset` from a wallet to an arbitrary recipient. This is
    /// the routine operational spend, so [`Role::Agent`] is enough - an
    /// autonomous executor can pay without holding administrative power - and it
    /// is still only permitted while the wallet is `Active`.
    pub fn transfer(
        env: Env,
        caller: Address,
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Agent)?;
        Self::require_active(&wallet)?;
        Self::debit(&env, wallet_id, &asset, amount)?;
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &to,
            &amount,
        );
        events::transfer_executed(&env, &env.current_contract_address(), &to, &asset, amount);
        Ok(())
    }

    /// Withdraw `amount` of `asset` from a wallet back to its owner. Funds
    /// leaving the wallet for its owner is an administrative action, so this
    /// requires [`Role::Admin`]; agents are deliberately excluded. Only
    /// permitted while the wallet is `Active`, and the destination is always
    /// the recorded owner regardless of who calls.
    pub fn withdraw(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        Self::require_active(&wallet)?;
        Self::debit(&env, wallet_id, &asset, amount)?;
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &wallet.owner,
            &amount,
        );
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("withdraw")),
            (wallet_id, asset, amount),
        );
        Ok(())
    }

    /// Freeze a wallet. Blocks all outbound movement. Freezing is a safety
    /// action, so [`Role::Agent`] is enough - an agent that detects trouble can
    /// stop the bleeding - as is the contract-level emergency admin.
    pub fn freeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role_or_admin(&env, wallet_id, &caller, Role::Agent)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }

        wallet.state = ResourceState::Frozen;
        Self::store_wallet(&env, wallet_id, &wallet);
        events::wallet_frozen(&env, wallet_id, &caller);
        events::publish(
            &env,
            events::ContractEvent::WalletStateChanged {
                wallet_id,
                state: symbol_short!("frozen"),
            },
        );
        Ok(())
    }

    /// Unfreeze a wallet back to `Active`. Same gate as `freeze`.
    pub fn unfreeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role_or_admin(&env, wallet_id, &caller, Role::Agent)?;
        if wallet.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unfrozen"));
        Ok(())
    }

    /// Pause a wallet ([`Role::Admin`]). Temporarily blocks outbound movement.
    pub fn pause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state != ResourceState::Active {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Paused;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("paused"));
        Ok(())
    }

    /// Resume a paused wallet ([`Role::Admin`]).
    pub fn unpause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state != ResourceState::Paused {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unpaused"));
        Ok(())
    }

    /// Archive a wallet ([`Role::Admin`]). Terminal state; no further
    /// transactions.
    pub fn archive(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }

        wallet.state = ResourceState::Archived;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("archived"));
        Ok(())
    }

    /// Delegate `role` on a wallet to `account`, replacing any role it already
    /// held. Requires [`Role::Admin`], so the owner (implicitly `Admin`) or an
    /// admin it has already delegated to may administer roles.
    ///
    /// Granting to the owner is refused: the owner is implicitly `Admin`, so the
    /// grant would either be redundant or an attempted demotion that the guards
    /// would ignore anyway. Refusing it keeps the stored roles honest.
    pub fn grant_role(
        env: Env,
        caller: Address,
        wallet_id: u64,
        account: Address,
        role: Role,
    ) -> Result<(), Error> {
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
        if account == wallet.owner {
            return Err(Error::InvalidInput);
        }
        access::set_role(&env, wallet_id, &account, role);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("granted")),
            (wallet_id, account, role),
        );
        Ok(())
    }

    /// Revoke whatever role `account` holds on a wallet. Requires
    /// [`Role::Admin`]. Fails with [`Error::NotFound`] when the account holds no
    /// granted role, so a revocation is never silently a no-op.
    ///
    /// Permitted on an archived wallet so role records can still be cleaned up.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        wallet_id: u64,
        account: Address,
    ) -> Result<(), Error> {
        Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        access::clear_role(&env, wallet_id, &account)?;
        env.events().publish(
            (symbol_short!("role"), symbol_short!("revoked")),
            (wallet_id, account),
        );
        Ok(())
    }

    /// Dispatch a wallet operation from an authorized caller.
    ///
    /// The `caller` must be one of:
    /// - the wallet's **owner** (verified against on-chain wallet state), or
    /// - a **registered module** for this wallet's organization, confirmed via
    ///   the on-chain registry contract.
    ///
    /// This is the primary entrypoint for organizational modules (multisig,
    /// treasury, policy, etc.) to execute wallet operations on behalf of the
    /// organization. Direct owner calls to `transfer` / `freeze` etc. remain
    /// available for backwards compatibility.
    ///
    /// # Errors
    /// - [`Error::UnauthorizedDispatch`] if the caller is neither the owner nor
    ///   a registered module.
    /// - Propagates any error from the underlying wallet operation.
    pub fn dispatch(
        env: Env,
        caller: Address,
        wallet_id: u64,
        action: WalletAction,
    ) -> Result<(), Error> {
        caller.require_auth();

        // Authorize: caller must be the wallet owner, the wallet admin, or a
        // registered module for this wallet's organization.
        Self::require_registered_caller(&env, &caller, wallet_id)?;

        Self::execute_dispatch(&env, wallet_id, &action)
    }

    // --- views ---

    /// Read the role `account` effectively holds on a wallet, or `None` if it
    /// holds none. The wallet owner always resolves to [`Role::Admin`].
    pub fn get_role(env: Env, wallet_id: u64, account: Address) -> Result<Option<Role>, Error> {
        let wallet = Self::load_wallet(&env, wallet_id)?;
        Ok(access::effective_role(
            &env,
            wallet_id,
            &wallet.owner,
            &account,
        ))
    }

    /// Whether `account` holds at least `role` on a wallet - the same question
    /// the entrypoint guards ask, exposed for off-chain callers.
    pub fn has_role(env: Env, wallet_id: u64, account: Address, role: Role) -> Result<bool, Error> {
        let wallet = Self::load_wallet(&env, wallet_id)?;
        Ok(access::require_role(&env, wallet_id, &wallet.owner, &account, role).is_ok())
    }

    /// Read a wallet's owner + state.
    pub fn get_wallet(env: Env, wallet_id: u64) -> Result<WalletData, Error> {
        Self::load_wallet(&env, wallet_id)
    }

    /// Read a wallet's internal balance for an asset (0 if none recorded).
    /// Stays available while the breaker is tripped.
    pub fn balance(env: Env, wallet_id: u64, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset))
            .unwrap_or(0)
    }

    /// Whether the contract-wide circuit breaker is currently tripped.
    pub fn is_paused(env: Env) -> bool {
        Self::paused(&env)
    }

    /// The address currently designated as emergency guardian.
    pub fn get_guardian(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Guardian)
            .ok_or(Error::NotInitialized)
    }

    // --- internal helpers ---

    fn load_wallet(env: &Env, id: u64) -> Result<WalletData, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Wallet(id))
            .ok_or(Error::NotFound)
    }

    fn store_wallet(env: &Env, id: u64, data: &WalletData) {
        env.storage().persistent().set(&DataKey::Wallet(id), data);
        Self::bump_wallet(env, id);
    }

    /// Authenticate `caller`, then require it to hold at least `required` on the
    /// wallet. The wallet is loaded first so an unknown id reports
    /// [`Error::NotFound`] rather than an authorization failure.
    fn require_wallet_role(
        env: &Env,
        id: u64,
        caller: &Address,
        required: Role,
    ) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        access::require_role(env, id, &wallet.owner, caller, required)?;

        Ok(wallet)
    }

    /// As [`Self::require_wallet_role`], but the contract-level emergency admin
    /// also passes regardless of any per-wallet role.
    fn require_wallet_role_or_admin(
        env: &Env,
        id: u64,
        caller: &Address,
        required: Role,
    ) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        let admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        if admin.map(|a| &a == caller).unwrap_or(false) {
            return Ok(wallet);
        }
        access::require_role(env, id, &wallet.owner, caller, required)?;

        Ok(wallet)
    }

    fn paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// The circuit breaker guard applied to every value-moving entrypoint.
    fn when_not_paused(env: &Env) -> Result<(), Error> {
        if Self::paused(env) {
            return Err(Error::WalletPaused);
        }
        Ok(())
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if &admin != caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_guardian_or_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        let guardian: Option<Address> = env.storage().instance().get(&DataKey::Guardian);
        let allowed = &admin == caller || guardian.map(|g| &g == caller).unwrap_or(false);
        if !allowed {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_active(wallet: &WalletData) -> Result<(), Error> {
        ensure!(wallet.state != ResourceState::Frozen, Error::WalletFrozen);
        ensure!(wallet.state != ResourceState::Paused, Error::WalletPaused);
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        Ok(())
    }

    fn credit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.safe_add(amount)?;
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    fn debit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientFunds);
        }
        let updated = current.safe_sub(amount)?;

        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    fn emit_state(env: &Env, id: u64, action: soroban_sdk::Symbol) {
        env.events()
            .publish((symbol_short!("wallet"), action.clone()), id);
        events::publish(
            env,
            events::ContractEvent::WalletStateChanged {
                wallet_id: id,
                state: action,
            },
        );
    }

    fn bump_wallet(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Wallet(id),
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    /// Verify that `caller` is the wallet owner, an admin, or has at least
    /// [`Role::Agent`] on the wallet.
    fn require_registered_caller(env: &Env, caller: &Address, wallet_id: u64) -> Result<(), Error> {
        let wallet = Self::load_wallet(env, wallet_id)?;
        let admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        if admin.as_ref() == Some(caller) {
            return Ok(());
        }
        access::require_role(env, wallet_id, &wallet.owner, caller, Role::Agent)
            .map_err(|_| Error::UnauthorizedDispatch)
    }

    /// Execute a dispatched wallet action.
    fn execute_dispatch(env: &Env, wallet_id: u64, action: &WalletAction) -> Result<(), Error> {
        match action {
            WalletAction::Transfer(WalletTransferAction { to, asset, amount }) => {
                require_positive_amount(*amount)?;
                let wallet = Self::load_wallet(env, wallet_id)?;
                Self::require_active(&wallet)?;
                Self::when_not_paused(env)?;
                Self::debit(env, wallet_id, asset, *amount)?;
                token::TokenClient::new(env, asset).transfer(
                    &env.current_contract_address(),
                    to,
                    amount,
                );
                events::publish(
                    env,
                    events::ContractEvent::TransferExecuted {
                        from: env.current_contract_address(),
                        to: to.clone(),
                        asset: asset.clone(),
                        amount: *amount,
                    },
                );
            }
            WalletAction::Withdraw(WalletWithdrawAction { asset, amount }) => {
                require_positive_amount(*amount)?;
                let wallet = Self::load_wallet(env, wallet_id)?;
                Self::require_active(&wallet)?;
                Self::when_not_paused(env)?;
                Self::debit(env, wallet_id, asset, *amount)?;
                let owner = wallet.owner.clone();
                token::TokenClient::new(env, asset).transfer(
                    &env.current_contract_address(),
                    &owner,
                    amount,
                );
                events::publish(
                    env,
                    events::ContractEvent::TransferExecuted {
                        from: env.current_contract_address(),
                        to: owner,
                        asset: asset.clone(),
                        amount: *amount,
                    },
                );
            }
            WalletAction::Freeze => {
                let mut wallet = Self::load_wallet(env, wallet_id)?;
                wallet.state = ResourceState::Frozen;
                Self::store_wallet(env, wallet_id, &wallet);
                Self::emit_state(env, wallet_id, symbol_short!("frozen"));
            }
            WalletAction::Unfreeze => {
                let mut wallet = Self::load_wallet(env, wallet_id)?;
                ensure!(wallet.state == ResourceState::Frozen, Error::InvalidState);
                wallet.state = ResourceState::Active;
                Self::store_wallet(env, wallet_id, &wallet);
                Self::emit_state(env, wallet_id, symbol_short!("active"));
            }
            WalletAction::Pause => {
                let mut wallet = Self::load_wallet(env, wallet_id)?;
                wallet.state = ResourceState::Paused;
                Self::store_wallet(env, wallet_id, &wallet);
                Self::emit_state(env, wallet_id, symbol_short!("paused"));
            }
            WalletAction::Unpause => {
                let mut wallet = Self::load_wallet(env, wallet_id)?;
                ensure!(wallet.state == ResourceState::Paused, Error::InvalidState);
                wallet.state = ResourceState::Active;
                Self::store_wallet(env, wallet_id, &wallet);
                Self::emit_state(env, wallet_id, symbol_short!("active"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
