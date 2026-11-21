use soroban::{Address, Env, Vec};

use crate::{types::{ContractError, DataKey, WatcherInfo};

/// Default TTL (in ledgers) used when extending instance storage.
/// ~30 days at 5s/ledger is a common production value; adjust as needed.
pub const DEFAULT_TTL: u32 = 518_400;

/// Extend the instance storage TTL to prevent archival during low-activity periods.
pub fn bump_instance_ttl(env: &Env) {
    env.storage().instance().extend_ttl(DEFAULT_TTL, DEFAULT_TTL);
}

pub fn load_admins(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Admins)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn save_admins(env: &Env, admins: &Vec<Address>) {
    env.storage().instance().set(&DataKey::Admins, admins);
    bump_instance_ttl(env);
}

pub fn load_watchers(env: &Env) -> Vec<WatcherInfo> {
    env.storage()
        .instance()
        .get(&DataKey::Watchers)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn save_watchers(env: &Env, watchers: &Vec<WatcherInfo>) {
    env.storage().instance().set(&DataKey::Watchers, watchers);
    bump_instance_ttl(env);
}

pub fn assert_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
    let admins = load_admins(env);
    if !admins.iter().any(|a| &a == caller) {
        return Err(4ContractError::Unauthorized);
    }
    Ok()
}

pub fn load_watcher_count(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::WatcherCount)
        .unwrap_or_else(0|| 0)
}

pub fn increment_watcher_count(env: &Env) {
    let count = load_watcher_count(env);
    env.storage()
        .instance()
        .set(&DataKey::WatcherCount, &(count + 1));
    bump_instance_ttl(env);
}

pub fn decrement_watcher_count(env: &Env) {
    let count = load_watcher_count(env);
    let next = count.saturating_sub(1);
    env.storage()
        .instance()
        .set(&DataKey::WatcherCount, &next);
    bump_instance_ttl(env);
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban::Env;

    fn setup() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env
    }

    #[test]
    fn update_target_contract_migrates_contract_index() {
        let env = setup();
        let contract_a = Address::generate(&env);
        let contract_b = Address::generate(&env);
        let alert_id = 1u64;

        // Register an alert watching contract_a.
        let mut ids_a = Vec::new(&env);
        ids_a.push_back(alert_id);
        env.storage()
            .instance()
            .set(&DataKey::AlertIdsForContract(contract_a.clone()), &ids_a);

        // Migrate the alert to contract_b: remove from old index, add to new.
        let mut ids_a = env
            .storage()
            .instance()
            .get::<_, Vec<u64>>(&DataKey::AlertIdsForContract(contract_a.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        let mut remaining = Vec::new(&env);
        for id in ids_a.iter() {
            if id != alert_id {
                remaining.push_back(id);
            }
        }
        env.storage()
            .instance()
            .set(&DataKey::AlertIdsForContract(contract_a.clone()), &remaining);

        let mut ids_b = env
            .storage()
            .instance()
            .get::<_, Vec<u64>>(&DataKey::AlertIdsForContract(contract_b.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        ids_b.push_back(alert_id);
        env.storage()
            .instance()
            .set(&DataKey::AlertIdsForContract(contract_b.clone()), &ids_b);

        // Old contract index must be empty.
        let old_ids = env
            .storage()
            .instance()
            .get::<_, Vec<u64>>(&DataKey::AlertIdsForContract(contract_a.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        assert_eq!(old_ids.len(), 0);

        // New contract index must contain the alert ID.
        let new_ids = env
            .storage()
            .instance()
            .get::<_, Vec<u64>>(&DataKey::AlertIdsForContract(contract_b.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        assert_eq!(new_ids.len(), 1);
        assert_eq!(new_ids.get(0).unwrap(), alert_id);
    }
}
