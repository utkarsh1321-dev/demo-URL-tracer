// ──────────────────────────────────────────────────────────────────────────────
// mock/mockData.js — REMOVED in Phase 1 (Remove Synthetic Data)
//
// This file previously contained ~25 KB of synthetic attack records, fake IP
// profiles, and hardcoded dashboard statistics used for demo/hackathon purposes.
//
// All exports are now empty. The file is retained only to prevent import errors
// in any component that has not yet been updated to remove the import.
//
// Phase 2: This file and all remaining imports of it will be deleted entirely.
// ──────────────────────────────────────────────────────────────────────────────

export const mockAttacks     = [];
export const mockDashboard   = {};
export const mockIPProfiles  = {};
export const mockPCAPResult  = {};
export const ATTACK_TYPES    = [];
export const DETECTION_METHODS = [];
export const SEVERITIES      = [];

export function getExportData()          { return { attacks: [], ips: [] }; }
export function getTopSourceIPs()        { return []; }
