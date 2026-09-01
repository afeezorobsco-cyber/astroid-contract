#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Policy Contract
//!
//! Verifies that a proposed transfer complies with the ACTIVE policy
//! configuration (PRD Doc 7 §Policy). The Astroid backend owns the human-facing
//! policy graph; this contract stores only a cryptographic hash of the active
//! configuration and a small set of scalar gates so on-chain verification is
//! cheap, fast and tamper-evident (PRD "Policy Hash Verification" enhancement).
//!
//! ```text
//! off-chain policy.json → hash → store on-chain
//! transaction → recompute hash of ACTIVE config → compare → allow / deny
//! ```
//!
//! This contract answers: "may `amount` of `asset` flow to `recipient`
//! right now?" with a deterministic [`Error`] when it may not.
//!
//! Functions: `initialize`, `register_policy`, `rotate_policy`, `set_allowance`,
//! `get_allowance`, `check_allowance`, `update_allowance`, `check_transfer`.
//!
//! ## Multi-token allowances
//!
//! A policy can attach a per-asset spending allowance to any policy. Each
//! Stellar asset type (native XLM or a Soroban SAC token) is tracked under its
//! own `(policy_id, asset)` key, so evaluation is safe against overflow and
//! cheap (single persistent read/write).
//!
//! ## Asset deny list
//!
//! Agents source their token lists off-chain, so a policy also owns an on-chain
//! asset deny list keyed by `(policy_id, asset)` and managed by the policy owner
//! through `add_asset_blacklist` / `remove_asset_blacklist`. `check_transfer`
//! probes it once and denies a listed asset with [`Error::PolicyDenied`] and an
//! `asset_blacklisted` violation reason. The deny list is evaluated after the
//! allow gates and wins over them, so blacklisting an allow-listed or
//! whitelisted asset takes effect immediately.
//!
//! A dedicated `AssetBlacklisted` error code would read better here, but
//! [`Error`] already carries the 50 cases a Soroban error enum may declare, so
//! the deny list reuses [`Error::PolicyDenied`] and is distinguished by its
//! violation event reason.

pub mod policy_rules;

use astroid_interfaces::PolicyInterface;
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::validation::{require_non_empty, require_non_negative_amount};
use policy_rules::PolicyRule;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String,
};

/// Maximum recursion depth for composite rule evaluation to prevent stack
/// overflows and excessive gas consumption on-chain.
const MAX_RULE_DEPTH: u32 = 10;

/// A transaction payload submitted for policy evaluation.
///
/// This struct carries the essential fields of a proposed transfer so the
/// composite rule engine can assess it against the full policy tree.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPayload {
    /// The Stellar asset contract address being transferred.
    pub asset: Address,
    /// The intended recipient of the transfer.
    pub recipient: Address,
    /// The amount being transferred (in base units).
    pub amount: i128,
}

/// The operation performed by a rule node.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RuleOp {
    /// Leaf: transfer amount must be at most `value_i128`.
    MaxAmount = 0,
    /// Leaf: recipient must equal `value_address`.
    AllowedRecipient = 1,
    /// Leaf: asset must equal `value_address`.
    AllowedAsset = 2,
    /// Leaf: recipient must be on the on-chain blacklist.
    RecipientBlacklisted = 3,
    /// Leaf: recipient must be on the merchant blacklist.
    MerchantBlacklisted = 4,
    /// Branch: **all** children must evaluate to `true`.
    And = 5,
    /// Branch: **at least one** child must evaluate to `true`.
    Or = 6,
    /// Branch: negates the single child rule.
    Not = 7,
}

/// A single node in a flattened composite rule tree.
///
/// Branch nodes (`And`, `Or`, `Not`) reference their children by index range
/// into the enclosing [`RuleTree`] vector. Leaf nodes use
/// `children_start == children_end == 0`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleNode {
    /// The operation this node performs.
    pub op: RuleOp,
    /// Payload for leaf nodes that carry an amount threshold.
    pub value_i128: i128,
    /// Payload for leaf nodes that carry an address.
    pub value_address: Address,
    /// Index of the first child in the tree vector (`0` = no children).
    pub children_start: u32,
    /// One past the last child index (`0` = no children).
    pub children_end: u32,
}

/// A flattened composite policy rule tree.
///
/// The root node is always at index **0**.  Children of a branch node at index
/// `i` occupy the contiguous range `[children_start, children_end)` in the
/// same vector.
///
/// **Gas safety:** Evaluation is depth-limited to [`MAX_RULE_DEPTH`].
pub type RuleTree = soroban_sdk::Vec<RuleNode>;

/// Evaluate a node in a [`RuleTree`] against `payload`.
///
/// `depth` is decremented on every recursive call; returns
/// `Err(Error::InvalidInput)` when exhausted (stack/gas protection).
fn evaluate_node(
    env: &Env,
    tree: &RuleTree,
    node_idx: u32,
    payload: &TransactionPayload,
    depth: u32,
) -> Result<bool, Error> {
    if depth == 0 {
        return Err(Error::InvalidInput);
    }
    let remaining = depth - 1;
    let node = tree.get(node_idx).ok_or(Error::InvalidInput)?;
    match node.op {
        RuleOp::MaxAmount => Ok(payload.amount <= node.value_i128),
        RuleOp::AllowedRecipient => Ok(payload.recipient == node.value_address),
        RuleOp::AllowedAsset => Ok(payload.asset == node.value_address),
        RuleOp::RecipientBlacklisted => Ok(env
            .storage()
            .persistent()
            .has(&DataKey::Blacklist(payload.recipient.clone()))),
        RuleOp::MerchantBlacklisted => Ok(env
            .storage()
            .persistent()
            .has(&DataKey::MerchantBlacklist(payload.recipient.clone()))),
        RuleOp::And => {
            if node.children_start == node.children_end {
                return Err(Error::InvalidInput);
            }
            for i in node.children_start..node.children_end {
                if !evaluate_node(env, tree, i, payload, remaining)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        RuleOp::Or => {
            if node.children_start == node.children_end {
                return Err(Error::InvalidInput);
            }
            for i in node.children_start..node.children_end {
                if evaluate_node(env, tree, i, payload, remaining)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        RuleOp::Not => {
            if node.children_start + 1 != node.children_end {
                return Err(Error::InvalidInput);
            }
            let result = evaluate_node(env, tree, node.children_start, payload, remaining)?;
            Ok(!result)
        }
    }
}

/// On-chain representation of a registered policy.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Admin that controls this policy (typically the treasury/admin wallet).
    pub owner: Address,
    /// SHA-256 hash of the human-readable policy JSON managed off-chain.
    pub config_hash: BytesN<32>,
    /// Scalar gates baked in for cheap on-chain checks (so we don't need JSON).
    pub max_amount: i128,
    /// Allow-listed recipient (zero-length means "any" is allowed).
    pub allowed_recipient: Option<Address>,
    /// Asset contract address the spend must be in (None = any asset).
    pub allowed_asset: Option<Address>,
    /// Unix timestamp the policy is active until (0 = no expiry).
    pub expires_at: u64,
    /// Whether the policy is currently enabled.
    pub enabled: bool,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Policy(String),
    Count,
    Blacklist(Address),
    MerchantBlacklist(Address),
    CategoryBlacklist(String),
    /// Per-policy asset whitelist: (policy_id, asset) -> true.
    AssetWhitelist(String, Address),
    /// Per-policy asset deny list: (policy_id, asset) -> (). Keyed by policy so
    /// each policy governs only its own assets.
    AssetBlacklist(String, Address),
    /// Whether an org uses a permissive (all-assets-allowed) or restrictive
    /// (whitelist-enforced) asset mode. Stored per policy_id.
    AssetWhitelistEnabled(String),
    /// Per-(policy, asset) multi-token spending allowance.
    Allowance(String, Address),
    /// Composite rule tree for a policy (set via `set_composite_rule`).
    CompositeRule(String),
}

/// A per-asset spending allowance attached to a policy.
///
/// Multiple Stellar asset types (native XLM and Soroban SAC tokens) are tracked
/// independently under the (policy_id, asset) key, so a policy can express a
/// granular quota per token rather than a single default denomination.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetAllowance {
    /// The policy this allowance belongs to.
    pub policy_id: String,
    /// The asset contract address (SAC) or the native XLM contract.
    pub asset: Address,
    /// Cumulative spending limit for this asset. `0` means disabled.
    pub limit: i128,
    /// Amount already spent against the limit.
    pub spent: i128,
    /// Unix timestamp the allowance expires at (`0` = never).
    pub expires_at: u64,
}

#[contract]
pub struct PolicyContract;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl PolicyContract {
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
    /// `wasm_hash` must be approved for [`ModuleKind::Policy`] in the registry.
    /// Any other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Policy,
            wasm_hash,
        )
    }
    pub fn initialize(env: Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Count) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Count, &0u32);
        Ok(())
    }

    /// Register a policy. `owner` gates subsequent rotations. Cheap scalar gates
    /// are stored on-chain; the full configuration is hashed for tamper-evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn register_policy(
        env: Env,
        owner: Address,
        policy_id: String,
        config_hash: BytesN<32>,
        max_amount: i128,
        allowed_recipient: Option<Address>,
        allowed_asset: Option<Address>,
        expires_at: u64,
    ) -> Result<(), Error> {
        owner.require_auth();
        require_non_empty(&policy_id)?;
        if env
            .storage()
            .persistent()
            .has(&DataKey::Policy(policy_id.clone()))
        {
            return Err(Error::AlreadyExists);
        }
        let policy = Policy {
            owner,
            config_hash,
            max_amount,
            allowed_recipient,
            allowed_asset,
            expires_at,
            enabled: true,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("registd")),
            policy_id,
        );
        Ok(())
    }

    /// Rotate an existing policy hash — e.g. after the backend recomputes it.
    pub fn rotate_policy(
        env: Env,
        caller: Address,
        policy_id: String,
        new_hash: BytesN<32>,
        new_max: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy.config_hash = new_hash;
        policy.max_amount = new_max;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rotated")),
            policy_id,
        );
        Ok(())
    }

    /// Disable / enable a policy (owner only).
    pub fn set_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy.enabled = enabled;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        Ok(())
    }

    /// Add an asset to the policy's whitelist (owner only). When the asset
    /// whitelist is enabled for a policy, only whitelisted assets are permitted
    /// in `check_transfer`.
    pub fn add_asset_to_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &true);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("asset_add")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Remove an asset from the policy's whitelist (owner only).
    pub fn remove_asset_from_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("asset_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Blacklist an asset for a policy (owner only). Once listed, no transfer
    /// evaluated against `policy_id` may move that token, whatever the policy's
    /// other asset gates say.
    pub fn add_asset_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::AssetBlacklist(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &());
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("ablk_add")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Remove an asset from a policy's blacklist (owner only).
    pub fn remove_asset_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::AssetBlacklist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("ablk_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Whether `asset` is blacklisted under `policy_id`.
    pub fn is_asset_blacklisted(env: Env, policy_id: String, asset: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::AssetBlacklist(policy_id, asset))
    }

    /// Enable or disable the asset whitelist for a policy (owner only).
    /// When enabled, only assets explicitly added via `add_asset_to_whitelist`
    /// are permitted.
    pub fn set_asset_whitelist_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelistEnabled(policy_id);
        env.storage().persistent().set(&key, &enabled);
        Ok(())
    }

    /// Check whether an asset is whitelisted for a given policy.
    /// Returns Ok(()) if allowed, or AssetNotWhitelisted if the whitelist is
    /// enabled and the asset is not present.
    pub fn validate_asset(env: Env, policy_id: String, asset: Address) -> Result<(), Error> {
        let enabled_key = DataKey::AssetWhitelistEnabled(policy_id.clone());
        let whitelist_enabled: bool = env
            .storage()
            .persistent()
            .get(&enabled_key)
            .unwrap_or(false);
        if !whitelist_enabled {
            return Ok(());
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            events_policy_violation(&env, &policy_id, "asset_not_whitelisted");
            return Err(Error::AssetNotWhitelisted);
        }
        Ok(())
    }

    /// Add an address to the restricted blacklist (owner only).
    pub fn add_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::Blacklist(address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_add")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Remove an address from the restricted blacklist (owner only).
    pub fn remove_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::Blacklist(address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_rem")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Add a merchant address to the merchant blacklist (owner only).
    pub fn add_merchant_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        merchant_address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::MerchantBlacklist(merchant_address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("merch_add")),
            (policy_id, merchant_address),
        );
        Ok(())
    }

    /// Remove a merchant address from the merchant blacklist (owner only).
    pub fn remove_merchant_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        merchant_address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::MerchantBlacklist(merchant_address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("merch_rem")),
            (policy_id, merchant_address),
        );
        Ok(())
    }

    /// Add a spending category to the category blacklist (owner only).
    pub fn add_category_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        category: String,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        require_non_empty(&category)?;
        let key = DataKey::CategoryBlacklist(category.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("cat_add")),
            (policy_id, category),
        );
        Ok(())
    }

    /// Remove a spending category from the category blacklist (owner only).
    pub fn remove_category_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        category: String,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::CategoryBlacklist(category.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("cat_rem")),
            (policy_id, category),
        );
        Ok(())
    }

    /// Add a recipient address to the blocklist (owner only). Blocked
    /// addresses are rejected immediately in `check_transfer` before any
    /// other policy gate is evaluated (Issue #32).
    pub fn add_to_blocklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Blacklist(address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_add")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Remove a recipient address from the blocklist (owner only).
    pub fn remove_from_blocklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Blacklist(address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_rem")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Check if a spending category is restricted. Returns Ok(()) if the category
    /// is allowed, or PolicyDenied if it's blacklisted.
    pub fn check_category(env: Env, policy_id: String, category: String) -> Result<(), Error> {
        // Empty category is always allowed
        if category.is_empty() {
            return Ok(());
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::CategoryBlacklist(category.clone()))
        {
            events_policy_violation(&env, &policy_id, "category_restricted");
            return Err(Error::PolicyDenied);
        }
        Ok(())
    }

    // --- multi-token allowances ---

    /// Create or update the spending allowance for `(policy_id, asset)`.
    /// `owner` only. Rejects a negative limit. `expires_at == 0` means never.
    pub fn set_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        limit: i128,
        expires_at: u64,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        require_non_negative_amount(limit)?;
        // Updating an allowance keeps existing spend so limits are enforced
        // cumulatively across updates.
        let mut allowance = Self::get_allowance(env.clone(), policy_id.clone(), asset.clone());
        allowance.limit = limit;
        allowance.expires_at = expires_at;
        allowance.policy_id = policy_id.clone();
        allowance.asset = asset.clone();
        env.storage().persistent().set(
            &DataKey::Allowance(policy_id.clone(), asset.clone()),
            &allowance,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_set")),
            (policy_id, asset, limit),
        );
        Ok(())
    }

    /// Remove the spending allowance for `(policy_id, asset)`. `owner` only.
    pub fn remove_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Allowance(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Read the current allowance for `(policy_id, asset)`. Returns the stored
    /// record, or a zeroed record when none has been configured (so callers can
    /// treat an unset allowance as "unrestricted").
    pub fn get_allowance(env: Env, policy_id: String, asset: Address) -> AssetAllowance {
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(policy_id.clone(), asset.clone()))
            .unwrap_or(AssetAllowance {
                policy_id,
                asset,
                limit: 0,
                spent: 0,
                expires_at: 0,
            })
    }

    /// Check whether spending `amount` of `asset` under `policy_id` is within
    /// the configured allowance. Returns the remaining headroom after the spend
    /// (0 = the allowance would be fully consumed, which is permitted). An
    /// unset allowance is unrestricted. Returns
    /// [`Error::PolicyAllowanceExceeded`] when the spend would breach the
    /// allowance.
    pub fn check_allowance(
        env: Env,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<i128, Error> {
        require_non_negative_amount(amount)?;
        let allowance = Self::get_allowance(env.clone(), policy_id.clone(), asset.clone());
        // No configured allowance => unrestricted for this asset.
        if allowance.limit == 0 {
            return Ok(i128::MAX);
        }
        if allowance.expires_at != 0 && env.ledger().timestamp() >= allowance.expires_at {
            events_policy_violation(&env, &policy_id, "allowance_expired");
            return Err(Error::PolicyDenied);
        }
        let headroom_after_spend = checked_sub(allowance.limit, allowance.spent)?;
        if amount > headroom_after_spend {
            events_policy_violation(&env, &policy_id, "allowance_exceeded");
            return Err(Error::PolicyAllowanceExceeded);
        }
        checked_sub(headroom_after_spend, amount)
    }

    /// Atomically consume `amount` against the `(policy_id, asset)` allowance.
    /// Returns `Ok(())` when the allowance was decremented, or
    /// [`Error::PolicyAllowanceExceeded`] when it would be breached.
    pub fn update_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        require_non_negative_amount(amount)?;
        let mut allowance = Self::get_allowance(env.clone(), policy_id.clone(), asset.clone());
        // No configured allowance => nothing to enforce.
        if allowance.limit == 0 {
            return Ok(());
        }
        if allowance.expires_at != 0 && env.ledger().timestamp() >= allowance.expires_at {
            return Err(Error::PolicyDenied);
        }
        let headroom_after_spend = checked_sub(allowance.limit, allowance.spent)?;
        if amount > headroom_after_spend {
            return Err(Error::PolicyAllowanceExceeded);
        }
        allowance.spent = checked_add(allowance.spent, amount)?;
        env.storage().persistent().set(
            &DataKey::Allowance(policy_id.clone(), asset.clone()),
            &allowance,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_use")),
            (policy_id, asset, amount, allowance.spent),
        );
        Ok(())
    }

    // --- composite rules ---

    /// Register or replace the composite rule tree for a policy.
    ///
    /// The rule tree is evaluated during `check_transfer` **after** all the
    /// standard scalar gates (blocklist, max amount, recipient, asset, etc.)
    /// have passed. If the rule tree evaluates to `false`, the transfer is
    /// denied with [`Error::PolicyDenied`].
    ///
    /// `owner` only. The tree must contain at least one node with the root at
    /// index 0.
    pub fn set_composite_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        rule_tree: RuleTree,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        if rule_tree.is_empty() {
            return Err(Error::InvalidInput);
        }
        let key = DataKey::CompositeRule(policy_id.clone());
        env.storage().persistent().set(&key, &rule_tree);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_set")),
            policy_id,
        );
        Ok(())
    }

    /// Remove the composite rule tree for a policy (owner only).
    pub fn clear_composite_rule(env: Env, caller: Address, policy_id: String) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::CompositeRule(policy_id.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_clr")),
            policy_id,
        );
        Ok(())
    }

    /// Read the composite rule tree for a policy, if one is set.
    pub fn get_composite_rule(env: Env, policy_id: String) -> Result<RuleTree, Error> {
        let key = DataKey::CompositeRule(policy_id.clone());
        env.storage().persistent().get(&key).ok_or(Error::NotFound)
    }

    /// Evaluate a composite rule tree against a transaction payload.
    ///
    /// Returns `Ok(true)` when the rule permits the transaction, or
    /// `Err(Error::PolicyDenied)` when it denies it. If no composite rule
    /// is registered for the policy the function returns `Ok(true)` (permissive
    /// default — standard scalar gates still apply).
    pub fn evaluate_composite_rule(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<bool, Error> {
        let key = DataKey::CompositeRule(policy_id.clone());
        let tree: RuleTree = match env.storage().persistent().get(&key) {
            Some(t) => t,
            None => return Ok(true),
        };
        if tree.is_empty() {
            return Ok(true);
        }
        evaluate_node(&env, &tree, 0, &payload, MAX_RULE_DEPTH)
    }

    // --- views ---

    pub fn get(env: Env, policy_id: String) -> Result<Policy, Error> {
        Self::load(&env, &policy_id)
    }

    /// Return the conditional rules registered for `policy_id`.
    pub fn get_rules(env: Env, policy_id: String) -> soroban_sdk::Vec<PolicyRule> {
        policy_rules::load_rules(&env, &policy_id)
    }

    // --- rule management ---

    /// Append a conditional rule to a policy (owner only).
    pub fn add_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        rule: PolicyRule,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy_rules::add_rule(&env, &policy_id, rule)?;
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_add")),
            policy_id,
        );
        Ok(())
    }

    /// Remove a conditional rule by id (owner only).
    pub fn remove_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        rule_id: String,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy_rules::remove_rule(&env, &policy_id, &rule_id)?;
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_rm")),
            (policy_id, rule_id),
        );
        Ok(())
    }

    // --- internals ---

    fn load(env: &Env, id: &String) -> Result<Policy, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Policy(id.clone()))
            .ok_or(Error::NotFound)
    }

    /// Authenticate `caller` and require it to own `policy_id`.
    fn require_policy_owner(env: &Env, caller: &Address, policy_id: &String) -> Result<(), Error> {
        caller.require_auth();
        if Self::load(env, policy_id)?.owner != *caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

/// Allow the interface trait to call `check_transfer` on this contract.
#[contractimpl]
impl PolicyInterface for PolicyContract {
    /// Evaluate a transfer request against the named policy. All gates must pass.
    ///
    /// Blocklist checks run **first** so that compromised or malicious
    /// addresses are rejected immediately, before any allowance, asset or
    /// amount evaluation (Issue #32).
    fn check_transfer(
        env: Env,
        policy_id: String,
        asset: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        let policy = Self::load(&env, &policy_id)?;
        // Disabled policies deny every spend.
        if !policy.enabled {
            events_policy_violation(&env, &policy_id, "disabled");
            return Err(Error::PolicyDenied);
        }
        // --- Blocklist checks (Issue #32) — evaluated first ---
        if env
            .storage()
            .persistent()
            .has(&DataKey::Blacklist(recipient.clone()))
        {
            events_policy_violation(&env, &policy_id, "blacklisted");
            return Err(Error::PolicyRecipientRestricted);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::MerchantBlacklist(recipient.clone()))
        {
            events_policy_violation(&env, &policy_id, "merchant_blocked");
            return Err(Error::PolicyDenied);
        }
        // --- Allowance / amount gates ---
        if policy.expires_at != 0 && env.ledger().timestamp() >= policy.expires_at {
            events_policy_violation(&env, &policy_id, "expired");
            return Err(Error::PolicyDenied);
        }
        if policy.max_amount != 0 && amount > policy.max_amount {
            events_policy_violation(&env, &policy_id, "above_max");
            return Err(Error::PolicyDenied);
        }
        if let Some(allow_recip) = &policy.allowed_recipient {
            if allow_recip.clone() != recipient {
                events_policy_violation(&env, &policy_id, "bad_recipient");
                return Err(Error::PolicyDenied);
            }
        }
        if let Some(allow_asset) = &policy.allowed_asset {
            if allow_asset.clone() != asset {
                events_policy_violation(&env, &policy_id, "bad_asset");
                return Err(Error::PolicyDenied);
            }
        }
        // The asset deny list wins over every allow gate, so blacklisting an
        // allow-listed or whitelisted asset takes effect immediately.
        if env
            .storage()
            .persistent()
            .has(&DataKey::AssetBlacklist(policy_id.clone(), asset.clone()))
        {
            events_policy_violation(&env, &policy_id, "asset_blacklisted");
            return Err(Error::PolicyDenied);
        }
        // Check asset whitelist (Issue #37)
        Self::validate_asset(env.clone(), policy_id.clone(), asset.clone())?;
        // Multi-token allowance gate: reject a spend that would breach the
        // per-(policy, asset) allowance. An unset allowance is unrestricted.
        Self::check_allowance(env.clone(), policy_id.clone(), asset.clone(), amount)?;
        // --- Flat conditional rule evaluation (policy_rules) ---
        if let Err(Error::RuleDenied) =
            policy_rules::evaluate_rules(&env, &policy_id, &recipient, &asset)
        {
            events_policy_violation(&env, &policy_id, "rule_denied");
            return Err(Error::RuleDenied);
        }
        // --- Composite rule evaluation ---
        let payload = TransactionPayload {
            asset: asset.clone(),
            recipient: recipient.clone(),
            amount,
        };
        let rule_result = Self::evaluate_composite_rule(env.clone(), policy_id.clone(), payload)?;
        if !rule_result {
            events_policy_violation(&env, &policy_id, "rule_denied");
            return Err(Error::PolicyDenied);
        }
        Ok(())
    }
}

/// Emit a `PolicyViolation` event with a stable reason symbol, using both the
/// legacy tuple-topic helper and the canonical [`ContractEvent`] schema.
fn events_policy_violation(env: &Env, policy_id: &String, reason: &str) {
    let r = soroban_sdk::Symbol::new(env, reason);
    astroid_shared::events::policy_violation(env, policy_id, r.clone());
    astroid_shared::events::publish(
        env,
        ContractEvent::PolicyViolation {
            policy_id: policy_id.clone(),
            reason: r,
        },
    );
}

#[cfg(test)]
mod test;
