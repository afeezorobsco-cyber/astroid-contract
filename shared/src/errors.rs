//! Deterministic, protocol-wide error codes.
//!
//! Every contract returns variants of this single enum so that off-chain
//! consumers (the Astroid API, SDK and dashboard) can map a stable `u32` code
//! to a meaningful message. Numeric values are grouped by domain and MUST NOT
//! be reordered or reused once released — they are part of the public ABI.

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    // --- Generic / lifecycle (1-6) ---
    NotFound = 1,
    AlreadyExists = 2,
    Unauthorized = 3,
    InvalidInput = 4,
    NotInitialized = 5,
    AlreadyInitialized = 6,

    // --- Value / arithmetic (10-12) ---
    InsufficientFunds = 10,
    Overflow = 11,
    InvalidAmount = 12,

    // --- Policy (20-27) ---
    PolicyDenied = 20,
    EmergencyLock = 21,
    PolicyRecipientRestricted = 22,
    /// The asset is not in the organization's whitelist.
    AssetNotWhitelisted = 24,
    /// A proposed spend would breach a per-asset spending allowance.
    PolicyAllowanceExceeded = 25,
    /// A conditional policy rule denied the transaction.
    RuleDenied = 26,

    // --- Registry (30-39) ---
    RegistryFrozen = 30,
    ModuleDeprecated = 31,

    // --- Budget (40-44) ---
    BudgetExceeded = 40,
    BudgetFrozen = 41,
    BudgetArchived = 42,
    AssetNotAuthorized = 43,
    BudgetExpired = 44,

    // --- Wallet (50-53) ---
    WalletFrozen = 50,
    WalletArchived = 51,
    WalletPaused = 52,
    InvalidState = 53,
    UnauthorizedDispatch = 54,

    // --- Multisig / approvals (61-69, 90-92) ---
    ThresholdNotMet = 61,
    AlreadySigned = 62,
    NotASigner = 63,
    InvalidThreshold = 64,
    TooManySigners = 66,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 67,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 68,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 69,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 90,
    /// A timelocked governance change was executed before its delay elapsed.
    TimelockNotExpired = 91,
    /// A caller without governance rights attempted to modify signers,
    /// weights or the threshold.
    UnauthorizedModification = 92,

    // --- Proposal (71-79) ---
    ProposalExpired = 71,
    InvalidProposalState = 72,
    ProposalNotApproved = 73,
    NotAnApprover = 74,
    CancellationWindowClosed = 75,
    /// A prerequisite proposal has not executed, so the dependent proposal may
    /// not execute yet.
    PrerequisiteNotMet = 78,
    /// A declared dependency would close a cycle in the dependency graph.
    CircularDependencyDetected = 79,

    // --- Escrow (81-82) ---
    TimeLockActive = 81,
    GraceActive = 82,

    // --- Treasury allowances (83-84) ---
    AllowanceExceeded = 83,
    AllowanceExpired = 84,

    // --- Interface versioning (95-99) ---
    /// The remote contract's interface version is older than the minimum
    /// required by the caller, or otherwise incompatible.
    InterfaceVersionMismatch = 95,
}
