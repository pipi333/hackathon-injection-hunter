/**
 * Move Contract for Injection Hunter - Threat Registry
 * 
 * This is a Sui Move smart contract for storing injection scan proofs
 * on the Sui blockchain.
 * 
 * To deploy:
 * 1. Install Sui CLI: https://docs.sui.io/build/install
 * 2. Initialize: sui genesis
 * 3. Publish: sui move publish
 */

module injection_hunter::threat_registry {
    use std::string::String;
    use std::option::Option;
    use sui::object::{Self, UID, ID};
    use sui::transfer;
    use sui::tx_context::{TxContext, sender};
    use sui::table::{Self, Table};

    /// ThreatRegistry - stores threat statistics and scan proofs
    struct ThreatRegistry has key {
        id: UID,
        scans: Table<String, ScanProof>,
        total_scans: u64,
        threat_stats: Table<String, u64>
    }

    /// ScanProof - individual scan record
    struct ScanProof has store, copy {
        scan_id: String,
        risk_level: String,
        threat_hash: String,
        timestamp: u64,
        threat_count: u64
    }

    /// Error codes
    const E_SCAN_NOT_FOUND: u64 = 1;
    const E_UNAUTHORIZED: u64 = 2;

    /// Initialize the registry (called once on module publish)
    fun init(ctx: &mut TxContext) {
        let registry = ThreatRegistry {
            id: object::new(ctx),
            scans: table::new(ctx),
            total_scans: 0,
            threat_stats: table::new(ctx)
        };
        transfer::share_object(registry);
    }

    /// Record a new scan proof on-chain
    public entry fun record_scan(
        registry: &mut ThreatRegistry,
        scan_id: String,
        risk_level: String,
        threat_hash: String,
        threat_count: u64,
        ctx: &TxContext
    ) {
        let proof = ScanProof {
            scan_id,
            risk_level,
            threat_hash,
            timestamp: tx_context::epoch(ctx),
            threat_count
        };

        // Store the proof
        registry.scans.add(proof.scan_id.copy(), proof);
        registry.total_scans = registry.total_scans + 1;
    }

    /// Update threat statistics
    public entry fun update_threat_stats(
        registry: &mut ThreatRegistry,
        threat_type: String,
        count: u64
    ) {
        if (registry.threat_stats.contains(&threat_type)) {
            let current = registry.threat_stats[threat_type.copy()];
            registry.threat_stats[threat_type] = current + count;
        } else {
            registry.threat_stats.add(threat_type, count);
        }
    }

    /// Get scan proof by ID
    public fun get_scan(registry: &ThreatRegistry, scan_id: String): Option<ScanProof> {
        if (registry.scans.contains(&scan_id)) {
            option::some(registry.scans[scan_id])
        } else {
            option::none()
        }
    }

    /// Get total scan count
    public fun get_total_scans(registry: &ThreatRegistry): u64 {
        registry.total_scans
    }

    /// Get threat statistics
    public fun get_threat_stats(registry: &ThreatRegistry, threat_type: String): u64 {
        if (registry.threat_stats.contains(&threat_type)) {
            registry.threat_stats[threat_type]
        } else {
            0
        }
    }

    /// Get all threat statistics
    public fun get_all_threat_stats(registry: &ThreatRegistry): &Table<String, u64> {
        &registry.threat_stats
    }

    /// View function for off-chain queries
    public fun view_registry(registry: &ThreatRegistry): (u64, u64) {
        (registry.total_scans, registry.threat_stats.length())
    }
}
