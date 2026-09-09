use crate::shared::{normalize_prefix, prefix_matches, read_json, read_toml};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
struct OwnerMap {
    #[serde(default)]
    owners: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct TestMap {
    #[serde(default)]
    tests: BTreeMap<String, TestSpec>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct TestSpec {
    command: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ProofLanes {
    #[serde(default)]
    lane: Vec<ProofLane>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ProofLane {
    name: String,
    command: String,
    #[serde(default)]
    rules_covered: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Catalog {
    owner_map: OwnerMap,
    test_map: TestMap,
    proof_lanes: ProofLanes,
}

impl Catalog {
    pub(crate) fn load(repo: &Path) -> Self {
        let owner_map = match read_json(repo.join("agent/owner-map.json")) {
            Some(value) => value,
            None => OwnerMap {
                owners: BTreeMap::new(),
            },
        };
        let test_map = match read_json(repo.join("agent/test-map.json")) {
            Some(value) => value,
            None => TestMap {
                tests: BTreeMap::new(),
            },
        };
        let proof_lanes = match read_toml(repo.join("agent/proof-lanes.toml")) {
            Some(value) => value,
            None => ProofLanes { lane: Vec::new() },
        };
        Self {
            owner_map,
            test_map,
            proof_lanes,
        }
    }

    pub(crate) fn owner_for_path(&self, path: &str) -> (String, String) {
        let matched = self
            .owner_map
            .owners
            .iter()
            .filter(|(prefix, _)| prefix_matches(prefix, path))
            .max_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then(a.cmp(b)))
            .map(|(prefix, owner)| (owner.clone(), normalize_prefix(prefix)));
        if let Some(found) = matched {
            found
        } else {
            ("unmapped".into(), "unmapped".into())
        }
    }

    pub(crate) fn test_for_path(&self, path: &str) -> (String, String) {
        let matched = self
            .test_map
            .tests
            .iter()
            .filter(|(prefix, _)| prefix_matches(prefix, path))
            .max_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then(a.cmp(b)))
            .map(|(prefix, spec)| {
                let route = normalize_prefix(prefix);
                let lane = if let Some(lane) = self
                    .proof_lanes
                    .lane
                    .iter()
                    .find(|lane| lane.command.trim() == spec.command.trim())
                {
                    lane.name.clone()
                } else {
                    "test-map".into()
                };
                (route, lane)
            });
        if let Some(found) = matched {
            found
        } else {
            ("unmapped".into(), "unmapped".into())
        }
    }

    pub(crate) fn test_command_for_path(&self, path: &str) -> Option<&str> {
        self.test_map
            .tests
            .iter()
            .filter(|(prefix, _)| prefix_matches(prefix, path))
            .max_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then(a.cmp(b)))
            .map(|(_, spec)| spec.command.trim())
    }

    pub(crate) fn lane_authenticates_rules(
        &self,
        lane_name: &str,
        command: &str,
        required_rules: &[String],
    ) -> bool {
        let mut lanes = self
            .proof_lanes
            .lane
            .iter()
            .filter(|lane| lane.name == lane_name);
        let Some(lane) = lanes.next() else {
            return false;
        };
        if lanes.next().is_some() || lane.command.trim() != command.trim() {
            return false;
        }
        let declared = lane
            .rules_covered
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        declared.len() == lane.rules_covered.len()
            && lane
                .rules_covered
                .iter()
                .all(|rule| !rule.is_empty() && rule.trim() == rule)
            && required_rules.iter().all(|rule| declared.contains(rule))
    }
}
