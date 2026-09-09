use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::*;
use crate::model::{
    SERVICE_AGGREGATION_RULE_VERSION, ServiceAggregationBatch, ServiceAggregationCluster,
    ServiceBatchRelationship, canonical_http_candidate, canonical_ssh_candidate,
    normalize_new_service,
};

const MAX_SERVICE_REVISIONS_PER_ITEM: usize = 20;
const MAX_SERVICE_BATCHES: usize = 20;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CatalogTarget {
    kind: ServiceItemKind,
    id: Uuid,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CatalogCandidate {
    key: String,
    site: String,
}

impl VaultSession {
    pub fn list_services(&self, query: Option<&str>) -> Result<Vec<ServiceSummary>, VaultError> {
        let query = query
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_lowercase);
        let mut services = self
            .payload()?
            .services
            .iter()
            .filter(|service| self.valid_service_record(service))
            .filter(|service| {
                query.as_ref().is_none_or(|query| {
                    service.name.to_lowercase().contains(query)
                        || service
                            .description
                            .as_ref()
                            .is_some_and(|value| value.to_lowercase().contains(query))
                        || service
                            .tags
                            .iter()
                            .any(|tag| tag.to_lowercase().contains(query))
                        || service
                            .sites
                            .iter()
                            .any(|site| site.to_lowercase().contains(query))
                })
            })
            .map(|service| self.service_summary(service))
            .collect::<Vec<_>>();
        services.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        Ok(services)
    }

    pub fn service_detail(&self, id: Uuid) -> Result<ServiceDetail, VaultError> {
        let service = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == id)
            .filter(|service| self.valid_service_record(service))
            .ok_or(VaultError::ServiceNotFound)?;
        let relationships = service
            .relationships
            .iter()
            .filter(|relationship| self.relationship_target_exists(relationship))
            .cloned()
            .collect::<Vec<_>>();
        let mut counts = ServiceItemCounts::default();
        for relationship in &relationships {
            counts.add(relationship.item_kind);
        }
        Ok(ServiceDetail {
            id: service.id,
            name: service.name.clone(),
            description: service.description.clone(),
            tags: service.tags.clone(),
            sites: service.sites.clone(),
            relationships,
            counts,
            created_at: service.created_at,
            updated_at: service.updated_at,
        })
    }

    pub fn add_service(
        &mut self,
        mut input: NewServiceRecord,
    ) -> Result<ServiceSummary, VaultError> {
        normalize_new_service(&mut input)?;
        let now = unix_time_now();
        let record = ServiceRecord {
            id: Uuid::new_v4(),
            name: input.name,
            description: input.description,
            tags: input.tags,
            sites: input.sites,
            relationships: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        let summary = self.service_summary(&record);
        self.payload_mut()?.services.push(record);
        Ok(summary)
    }

    pub fn update_service(
        &mut self,
        input: ServiceRecordUpdate,
    ) -> Result<ServiceSummary, VaultError> {
        let mut normalized = NewServiceRecord {
            name: input.name,
            description: input.description,
            tags: input.tags,
            sites: input.sites,
        };
        normalize_new_service(&mut normalized)?;
        let now = unix_time_now();
        let existing = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == input.id)
            .cloned()
            .ok_or(VaultError::ServiceNotFound)?;
        self.push_service_history(existing, now)?;
        let service = self
            .payload_mut()?
            .services
            .iter_mut()
            .find(|service| service.id == input.id)
            .ok_or(VaultError::ServiceNotFound)?;
        service.name = normalized.name;
        service.description = normalized.description;
        service.tags = normalized.tags;
        service.sites = normalized.sites;
        service.updated_at = now;
        let service = service.clone();
        Ok(self.service_summary(&service))
    }

    pub fn delete_service(&mut self, id: Uuid) -> Result<(), VaultError> {
        let now = unix_time_now();
        let payload = self.payload_mut()?;
        let index = payload
            .services
            .iter()
            .position(|service| service.id == id)
            .ok_or(VaultError::ServiceNotFound)?;
        let item = payload.services.remove(index);
        session_api_environment::bump_api_environments_for_service(payload, id);
        payload.service_trash.push(TrashedServiceRecord {
            trash_id: Uuid::new_v4(),
            deleted_at: now,
            item,
        });
        Ok(())
    }

    pub fn list_service_trash(&self) -> Result<Vec<ServiceTrashSummary>, VaultError> {
        let mut trash = self
            .payload()?
            .service_trash
            .iter()
            .map(|entry| ServiceTrashSummary {
                trash_id: entry.trash_id,
                service_id: entry.item.id,
                name: entry.item.name.clone(),
                deleted_at: entry.deleted_at,
            })
            .collect::<Vec<_>>();
        trash.sort_by_key(|entry| std::cmp::Reverse(entry.deleted_at));
        Ok(trash)
    }

    pub fn restore_service_trash(&mut self, trash_id: Uuid) -> Result<ServiceSummary, VaultError> {
        let payload = self.payload()?;
        let index = payload
            .service_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        if payload
            .services
            .iter()
            .any(|service| service.id == payload.service_trash[index].item.id)
        {
            return Err(VaultError::InvalidService);
        }
        let payload = self.payload_mut()?;
        let mut entry = payload.service_trash.remove(index);
        entry.item.updated_at = unix_time_now();
        let item = entry.item;
        session_api_environment::bump_api_environments_for_service(payload, item.id);
        let summary = service_summary_with(
            |relationship| relationship_target_exists_in(payload, relationship),
            &item,
        );
        payload.services.push(item);
        Ok(summary)
    }

    pub fn purge_service_trash(&mut self, trash_id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .service_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let service_id = payload.service_trash[index].item.id;
        payload.service_trash.remove(index);
        payload
            .service_history
            .retain(|revision| revision.service_id != service_id);
        session_api_environment::purge_api_environments_for_service(payload, service_id);
        Ok(())
    }

    pub fn empty_service_trash(&mut self) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let ids = payload
            .service_trash
            .iter()
            .map(|entry| entry.item.id)
            .collect::<HashSet<_>>();
        payload.service_trash.clear();
        payload
            .service_history
            .retain(|revision| !ids.contains(&revision.service_id));
        for id in ids {
            session_api_environment::purge_api_environments_for_service(payload, id);
        }
        Ok(())
    }

    pub fn service_history(&self, id: Uuid) -> Result<Vec<ServiceRevisionSummary>, VaultError> {
        let mut revisions = self
            .payload()?
            .service_history
            .iter()
            .filter(|revision| revision.service_id == id)
            .map(|revision| ServiceRevisionSummary {
                revision_id: revision.revision_id,
                service_id: revision.service_id,
                name: revision.item.name.clone(),
                saved_at: revision.saved_at,
            })
            .collect::<Vec<_>>();
        revisions.sort_by_key(|revision| std::cmp::Reverse(revision.saved_at));
        Ok(revisions)
    }

    pub fn restore_service_revision(
        &mut self,
        service_id: Uuid,
        revision_id: Uuid,
    ) -> Result<ServiceSummary, VaultError> {
        let revision = self
            .payload()?
            .service_history
            .iter()
            .find(|revision| {
                revision.service_id == service_id && revision.revision_id == revision_id
            })
            .cloned()
            .ok_or(VaultError::RevisionNotFound)?;
        let current = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == service_id)
            .cloned()
            .ok_or(VaultError::ServiceNotFound)?;
        let now = unix_time_now();
        self.push_service_history(current, now)?;
        let payload = self.payload_mut()?;
        let index = payload
            .services
            .iter()
            .position(|service| service.id == service_id)
            .ok_or(VaultError::ServiceNotFound)?;
        let mut restored = revision.item;
        restored.updated_at = now;
        payload.services[index] = restored.clone();
        Ok(service_summary_with(
            |relationship| relationship_target_exists_in(payload, relationship),
            &restored,
        ))
    }

    pub fn clear_service_history(&mut self, id: Uuid) -> Result<(), VaultError> {
        crate::sync::record_history_clear(self.payload_mut()?, "service_history", id)?;
        self.payload_mut()?
            .service_history
            .retain(|revision| revision.service_id != id);
        Ok(())
    }

    pub fn link_service_item(
        &mut self,
        service_id: Uuid,
        mut relationship: ServiceRelationship,
    ) -> Result<ServiceDetail, VaultError> {
        if !self.relationship_target_exists(&relationship) {
            return Err(VaultError::InvalidService);
        }
        let now = unix_time_now();
        let existing = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == service_id)
            .cloned()
            .ok_or(VaultError::ServiceNotFound)?;
        if let Some(current) = existing
            .relationships
            .iter()
            .find(|current| current.same_target(&relationship))
        {
            if current.source == ServiceRelationshipSource::Manual
                || current.source == relationship.source
            {
                return self.service_detail(service_id);
            }
            relationship.source = ServiceRelationshipSource::Manual;
        }
        self.push_service_history(existing, now)?;
        let service = self
            .payload_mut()?
            .services
            .iter_mut()
            .find(|service| service.id == service_id)
            .ok_or(VaultError::ServiceNotFound)?;
        service
            .relationships
            .retain(|current| !current.same_target(&relationship));
        service.relationships.push(relationship);
        sort_relationships(&mut service.relationships);
        service.updated_at = now;
        self.service_detail(service_id)
    }

    pub fn unlink_service_item(
        &mut self,
        service_id: Uuid,
        relationship: &ServiceRelationship,
    ) -> Result<ServiceDetail, VaultError> {
        let existing = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == service_id)
            .cloned()
            .ok_or(VaultError::ServiceNotFound)?;
        if !existing
            .relationships
            .iter()
            .any(|current| current.same_target(relationship))
        {
            return self.service_detail(service_id);
        }
        let now = unix_time_now();
        self.push_service_history(existing, now)?;
        let service = self
            .payload_mut()?
            .services
            .iter_mut()
            .find(|service| service.id == service_id)
            .ok_or(VaultError::ServiceNotFound)?;
        service
            .relationships
            .retain(|current| !current.same_target(relationship));
        service.updated_at = now;
        self.service_detail(service_id)
    }

    pub fn move_service_item(
        &mut self,
        from_id: Uuid,
        to_id: Uuid,
        mut relationship: ServiceRelationship,
    ) -> Result<ServiceDetail, VaultError> {
        if from_id == to_id || !self.relationship_target_exists(&relationship) {
            return Err(VaultError::InvalidService);
        }
        let payload = self.payload()?;
        let source = payload
            .services
            .iter()
            .find(|service| service.id == from_id)
            .ok_or(VaultError::ServiceNotFound)?;
        if !payload.services.iter().any(|service| service.id == to_id)
            || !source
                .relationships
                .iter()
                .any(|current| current.same_target(&relationship))
        {
            return Err(VaultError::InvalidService);
        }
        relationship.source = ServiceRelationshipSource::Manual;
        self.unlink_service_item(from_id, &relationship)?;
        self.link_service_item(to_id, relationship)
    }

    pub fn merge_services(
        &mut self,
        source_id: Uuid,
        destination_id: Uuid,
    ) -> Result<ServiceDetail, VaultError> {
        if source_id == destination_id {
            return Err(VaultError::InvalidService);
        }
        let source = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == source_id)
            .cloned()
            .ok_or(VaultError::ServiceNotFound)?;
        let destination = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == destination_id)
            .cloned()
            .ok_or(VaultError::ServiceNotFound)?;
        let now = unix_time_now();
        self.push_service_history(destination, now)?;
        let payload = self.payload_mut()?;
        let destination_index = payload
            .services
            .iter()
            .position(|service| service.id == destination_id)
            .ok_or(VaultError::ServiceNotFound)?;
        {
            let destination = &mut payload.services[destination_index];
            destination.tags.extend(source.tags.clone());
            destination.tags.sort();
            destination.tags.dedup();
            destination.sites.extend(source.sites.clone());
            destination.sites.sort();
            destination.sites.dedup();
            for mut relationship in source.relationships.clone() {
                relationship.source = ServiceRelationshipSource::Manual;
                destination
                    .relationships
                    .retain(|current| !current.same_target(&relationship));
                destination.relationships.push(relationship);
            }
            sort_relationships(&mut destination.relationships);
            destination.updated_at = now;
        }
        let source_index = payload
            .services
            .iter()
            .position(|service| service.id == source_id)
            .ok_or(VaultError::ServiceNotFound)?;
        let source = payload.services.remove(source_index);
        session_api_environment::bump_api_environments_for_service(payload, source_id);
        payload.service_trash.push(TrashedServiceRecord {
            trash_id: Uuid::new_v4(),
            deleted_at: now,
            item: source,
        });
        self.service_detail(destination_id)
    }

    pub fn split_service(
        &mut self,
        source_id: Uuid,
        mut input: NewServiceRecord,
        relationships: Vec<ServiceRelationship>,
    ) -> Result<ServiceDetail, VaultError> {
        normalize_new_service(&mut input)?;
        if relationships.is_empty()
            || relationships
                .iter()
                .any(|relationship| !self.relationship_target_exists(relationship))
        {
            return Err(VaultError::InvalidService);
        }
        let source = self
            .payload()?
            .services
            .iter()
            .find(|service| service.id == source_id)
            .cloned()
            .ok_or(VaultError::ServiceNotFound)?;
        if relationships.iter().any(|relationship| {
            !source
                .relationships
                .iter()
                .any(|current| current.same_target(relationship))
        }) {
            return Err(VaultError::InvalidService);
        }
        let now = unix_time_now();
        self.push_service_history(source, now)?;
        let new_id = Uuid::new_v4();
        let mut moved = relationships;
        for relationship in &mut moved {
            relationship.source = ServiceRelationshipSource::Manual;
        }
        sort_relationships(&mut moved);
        let payload = self.payload_mut()?;
        let source = payload
            .services
            .iter_mut()
            .find(|service| service.id == source_id)
            .ok_or(VaultError::ServiceNotFound)?;
        source.relationships.retain(|current| {
            !moved
                .iter()
                .any(|relationship| relationship.same_target(current))
        });
        source.updated_at = now;
        payload.services.push(ServiceRecord {
            id: new_id,
            name: input.name,
            description: input.description,
            tags: input.tags,
            sites: input.sites,
            relationships: moved,
            created_at: now,
            updated_at: now,
        });
        self.service_detail(new_id)
    }

    pub fn ignore_service_suggestion(
        &mut self,
        suggestion: ServiceIgnoredSuggestion,
    ) -> Result<(), VaultError> {
        if !suggestion.service_key.starts_with("host-v1:")
            || !self.relationship_target_exists(&ServiceRelationship {
                item_kind: suggestion.item_kind,
                item_id: suggestion.item_id,
                source: ServiceRelationshipSource::Manual,
            })
        {
            return Err(VaultError::InvalidService);
        }
        let ignored = &mut self.payload_mut()?.service_ignored_suggestions;
        if !ignored.iter().any(|current| {
            current.service_key == suggestion.service_key
                && current.item_kind == suggestion.item_kind
                && current.item_id == suggestion.item_id
        }) {
            ignored.push(suggestion);
        }
        Ok(())
    }

    pub fn service_automatic_linking_enabled(&self) -> Result<bool, VaultError> {
        Ok(!self.payload()?.service_automatic_linking_disabled)
    }

    pub fn set_service_automatic_linking_enabled(
        &mut self,
        enabled: bool,
    ) -> Result<bool, VaultError> {
        self.payload_mut()?.service_automatic_linking_disabled = !enabled;
        Ok(enabled)
    }

    pub fn service_aggregation_plan(&self) -> Result<ServiceAggregationPlan, VaultError> {
        let catalog = self.service_catalog()?;
        let labels = self.service_catalog_labels()?;
        let stable_catalog = catalog.iter().collect::<Vec<_>>();
        let stable_labels = labels.iter().collect::<Vec<_>>();
        let mut service_state = self.payload()?.services.clone();
        service_state.sort_by_key(|service| service.id);
        for service in &mut service_state {
            sort_relationships(&mut service.relationships);
        }
        let mut ignored_state = self.payload()?.service_ignored_suggestions.clone();
        ignored_state.sort_by_key(|ignored| {
            (
                ignored.item_kind,
                ignored.item_id,
                ignored.service_key.clone(),
            )
        });
        let encoded =
            serde_json::to_vec(&(stable_catalog, stable_labels, service_state, ignored_state))
                .map_err(|_| VaultError::Serialization)?;
        let input_digest = hex_digest(&encoded);
        let vault_namespace = hex_digest(
            &[
                b"vaultmesh-service-namespace-v1".as_slice(),
                self.header.salt.as_slice(),
            ]
            .concat(),
        );
        let plan_id = hex_digest(
            format!("{vault_namespace}:{SERVICE_AGGREGATION_RULE_VERSION}:{input_digest}")
                .as_bytes(),
        );
        let payload = self.payload()?;
        let mut services_by_key: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
        for service in &payload.services {
            for site in &service.sites {
                if let Some((key, _)) = canonical_http_candidate(site) {
                    services_by_key.entry(key).or_default().push(service.id);
                }
            }
        }
        let manual_targets = payload
            .services
            .iter()
            .flat_map(|service| &service.relationships)
            .filter(|relationship| relationship.source == ServiceRelationshipSource::Manual)
            .map(|relationship| CatalogTarget {
                kind: relationship.item_kind,
                id: relationship.item_id,
            })
            .collect::<BTreeSet<_>>();
        let mut cluster_map: BTreeMap<String, ServiceAggregationCluster> = BTreeMap::new();
        let mut conflicts = 0_u32;
        let mut ungrouped = 0_u32;
        let mut review_items = Vec::new();
        for (target, candidates) in &catalog {
            if manual_targets.contains(target) {
                continue;
            }
            let keys = candidates
                .iter()
                .map(|candidate| candidate.key.as_str())
                .collect::<BTreeSet<_>>();
            if keys.is_empty() {
                ungrouped = ungrouped.saturating_add(1);
                review_items.push(ServiceAggregationReviewItem {
                    item_kind: target.kind,
                    item_id: target.id,
                    label: labels
                        .get(target)
                        .cloned()
                        .unwrap_or_else(|| "未命名项目".to_owned()),
                    reason: ServiceAggregationReviewReason::NoSafeKey,
                });
                continue;
            }
            if keys.len() != 1 {
                conflicts = conflicts.saturating_add(1);
                review_items.push(ServiceAggregationReviewItem {
                    item_kind: target.kind,
                    item_id: target.id,
                    label: labels
                        .get(target)
                        .cloned()
                        .unwrap_or_else(|| "未命名项目".to_owned()),
                    reason: ServiceAggregationReviewReason::ConflictingMetadata,
                });
                continue;
            }
            let candidate = &candidates[0];
            if payload.service_ignored_suggestions.iter().any(|ignored| {
                ignored.service_key == candidate.key
                    && ignored.item_kind == target.kind
                    && ignored.item_id == target.id
            }) {
                continue;
            }
            let existing = services_by_key
                .get(&candidate.key)
                .cloned()
                .unwrap_or_default();
            if existing.len() > 1 {
                conflicts = conflicts.saturating_add(1);
                review_items.push(ServiceAggregationReviewItem {
                    item_kind: target.kind,
                    item_id: target.id,
                    label: labels
                        .get(target)
                        .cloned()
                        .unwrap_or_else(|| "未命名项目".to_owned()),
                    reason: ServiceAggregationReviewReason::ConflictingMetadata,
                });
                continue;
            }
            let existing_service_id = existing.first().copied();
            let relationship = ServiceRelationship {
                item_kind: target.kind,
                item_id: target.id,
                source: ServiceRelationshipSource::AutomaticExactHostV1,
            };
            if existing_service_id.is_some_and(|id| {
                payload
                    .services
                    .iter()
                    .find(|service| service.id == id)
                    .is_some_and(|service| {
                        service
                            .relationships
                            .iter()
                            .any(|current| current.same_target(&relationship))
                    })
            }) {
                continue;
            }
            cluster_map
                .entry(candidate.key.clone())
                .or_insert_with(|| ServiceAggregationCluster {
                    service_key: candidate.key.clone(),
                    suggested_name: candidate.key.trim_start_matches("host-v1:").to_owned(),
                    suggested_site: candidate.site.clone(),
                    existing_service_id,
                    reason: "exact canonical host".to_owned(),
                    relationships: Vec::new(),
                })
                .relationships
                .push(relationship);
        }
        let mut clusters = cluster_map.into_values().collect::<Vec<_>>();
        for cluster in &mut clusters {
            sort_relationships(&mut cluster.relationships);
        }
        review_items.sort_by(|left, right| {
            left.label
                .to_lowercase()
                .cmp(&right.label.to_lowercase())
                .then(left.item_kind.cmp(&right.item_kind))
                .then(left.item_id.cmp(&right.item_id))
        });
        let high_confidence_item_count = clusters
            .iter()
            .map(|cluster| cluster.relationships.len() as u32)
            .sum();
        Ok(ServiceAggregationPlan {
            plan_id,
            vault_namespace,
            catalog_revision: input_digest.clone(),
            rule_version: SERVICE_AGGREGATION_RULE_VERSION.to_owned(),
            input_digest,
            clusters,
            review_items,
            high_confidence_item_count,
            conflict_count: conflicts,
            ungrouped_count: ungrouped,
        })
    }

    pub fn apply_service_aggregation_plan(
        &mut self,
        plan_id: &str,
    ) -> Result<ServiceAggregationApplyResult, VaultError> {
        if let Some(batch) = self
            .payload()?
            .service_aggregation_batches
            .iter()
            .find(|batch| batch.plan_id == plan_id)
        {
            return Ok(ServiceAggregationApplyResult {
                batch_id: batch.batch_id,
                created_service_count: batch.created_service_ids.len() as u32,
                linked_item_count: batch.added_relationships.len() as u32,
                already_applied: true,
            });
        }
        let plan = self.service_aggregation_plan()?;
        if plan.plan_id != plan_id {
            return Err(VaultError::ServiceAggregationPlanExpired);
        }
        let now = unix_time_now();
        let mut batch = ServiceAggregationBatch {
            batch_id: Uuid::new_v4(),
            plan_id: plan.plan_id,
            applied_at: now,
            created_service_ids: Vec::new(),
            added_relationships: Vec::new(),
        };
        let payload = self.payload_mut()?;
        for cluster in plan.clusters {
            let service_id = if let Some(id) = cluster.existing_service_id {
                id
            } else {
                let id = Uuid::new_v4();
                payload.services.push(ServiceRecord {
                    id,
                    name: cluster.suggested_name,
                    description: None,
                    tags: Vec::new(),
                    sites: vec![cluster.suggested_site],
                    relationships: Vec::new(),
                    created_at: now,
                    updated_at: now,
                });
                batch.created_service_ids.push(id);
                id
            };
            let service = payload
                .services
                .iter_mut()
                .find(|service| service.id == service_id)
                .ok_or(VaultError::ServiceNotFound)?;
            for relationship in cluster.relationships {
                if !service
                    .relationships
                    .iter()
                    .any(|current| current.same_target(&relationship))
                {
                    service.relationships.push(relationship.clone());
                    batch.added_relationships.push(ServiceBatchRelationship {
                        service_id,
                        relationship,
                    });
                }
            }
            sort_relationships(&mut service.relationships);
            service.updated_at = now;
        }
        let result = ServiceAggregationApplyResult {
            batch_id: batch.batch_id,
            created_service_count: batch.created_service_ids.len() as u32,
            linked_item_count: batch.added_relationships.len() as u32,
            already_applied: false,
        };
        payload.service_aggregation_batches.push(batch);
        if payload.service_aggregation_batches.len() > MAX_SERVICE_BATCHES {
            payload.service_aggregation_batches.remove(0);
        }
        Ok(result)
    }

    pub fn rollback_service_aggregation_batch(&mut self, batch_id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .service_aggregation_batches
            .iter()
            .position(|batch| batch.batch_id == batch_id)
            .ok_or(VaultError::ItemNotFound)?;
        let batch = payload.service_aggregation_batches.remove(index);
        for added in &batch.added_relationships {
            if let Some(service) = payload
                .services
                .iter_mut()
                .find(|service| service.id == added.service_id)
            {
                service
                    .relationships
                    .retain(|relationship| !relationship.same_target(&added.relationship));
            }
        }
        payload.services.retain(|service| {
            !batch.created_service_ids.contains(&service.id)
                || !service.relationships.is_empty()
                || service.updated_at != batch.applied_at
        });
        Ok(())
    }

    /// Links newly added or updated items only when rule v1 resolves to one
    /// already-existing Service. It never creates a Service or applies a
    /// medium/low-confidence suggestion.
    pub fn reconcile_service_automatic_links(&mut self) -> Result<u32, VaultError> {
        if !self.service_automatic_linking_enabled()? {
            return Ok(0);
        }
        let catalog = self.service_catalog()?;
        let valid_keys = catalog
            .iter()
            .filter_map(|(target, candidates)| {
                let keys = candidates
                    .iter()
                    .map(|candidate| candidate.key.clone())
                    .collect::<BTreeSet<_>>();
                (keys.len() == 1)
                    .then(|| (target.clone(), keys.into_iter().next().expect("one key")))
            })
            .collect::<BTreeMap<_, _>>();
        let service_keys = self
            .payload()?
            .services
            .iter()
            .map(|service| {
                let keys = service
                    .sites
                    .iter()
                    .filter_map(|site| canonical_http_candidate(site).map(|(key, _)| key))
                    .collect::<BTreeSet<_>>();
                (service.id, keys)
            })
            .collect::<BTreeMap<_, _>>();
        {
            let payload = self.payload_mut()?;
            for service in &mut payload.services {
                let keys = service_keys.get(&service.id);
                let relationship_count = service.relationships.len();
                service.relationships.retain(|relationship| {
                    relationship.source == ServiceRelationshipSource::Manual
                        || valid_keys
                            .get(&CatalogTarget {
                                kind: relationship.item_kind,
                                id: relationship.item_id,
                            })
                            .is_some_and(|key| keys.is_some_and(|keys| keys.contains(key)))
                });
                if service.relationships.len() != relationship_count {
                    service.updated_at = unix_time_now();
                }
            }
        }
        let plan = self.service_aggregation_plan()?;
        let mut linked = 0_u32;
        let payload = self.payload_mut()?;
        for cluster in plan
            .clusters
            .into_iter()
            .filter(|cluster| cluster.existing_service_id.is_some())
        {
            let service_id = cluster
                .existing_service_id
                .expect("filtered existing service");
            let service = payload
                .services
                .iter_mut()
                .find(|service| service.id == service_id)
                .ok_or(VaultError::ServiceNotFound)?;
            let mut service_linked = false;
            for relationship in cluster.relationships {
                if !service
                    .relationships
                    .iter()
                    .any(|current| current.same_target(&relationship))
                {
                    service.relationships.push(relationship);
                    linked = linked.saturating_add(1);
                    service_linked = true;
                }
            }
            sort_relationships(&mut service.relationships);
            if service_linked {
                service.updated_at = unix_time_now();
            }
        }
        Ok(linked)
    }

    fn service_catalog(
        &self,
    ) -> Result<BTreeMap<CatalogTarget, Vec<CatalogCandidate>>, VaultError> {
        let payload = self.payload()?;
        let mut catalog: BTreeMap<CatalogTarget, BTreeSet<CatalogCandidate>> = BTreeMap::new();
        for item in &payload.items {
            let target = CatalogTarget {
                kind: ServiceItemKind::Login,
                id: item.id,
            };
            for value in item.url.iter().chain(&item.additional_urls) {
                if let Some((key, site)) = canonical_http_candidate(value) {
                    catalog
                        .entry(target.clone())
                        .or_default()
                        .insert(CatalogCandidate { key, site });
                }
            }
            catalog.entry(target).or_default();
        }
        for item in &payload.secrets {
            let summary = crate::SecretItemSummary::from(item);
            let target = if summary.is_passkey {
                summary
                    .login_id
                    .filter(|id| payload.items.iter().any(|login| login.id == *id))
                    .map(|id| CatalogTarget {
                        kind: ServiceItemKind::Login,
                        id,
                    })
                    .unwrap_or(CatalogTarget {
                        kind: ServiceItemKind::Secret,
                        id: item.id,
                    })
            } else {
                CatalogTarget {
                    kind: ServiceItemKind::Secret,
                    id: item.id,
                }
            };
            if let Some((key, site)) = item.website.as_deref().and_then(canonical_http_candidate) {
                catalog
                    .entry(target.clone())
                    .or_default()
                    .insert(CatalogCandidate { key, site });
            }
            catalog.entry(target).or_default();
        }
        for item in &payload.ssh_items {
            let target = CatalogTarget {
                kind: ServiceItemKind::Ssh,
                id: item.id,
            };
            if let Some((key, site)) = item
                .host
                .as_deref()
                .and_then(|host| canonical_ssh_candidate(host, item.port))
            {
                catalog
                    .entry(target.clone())
                    .or_default()
                    .insert(CatalogCandidate { key, site });
            }
            catalog.entry(target).or_default();
        }
        for item in &payload.identities {
            let target = CatalogTarget {
                kind: ServiceItemKind::Identity,
                id: item.id,
            };
            if let Some((key, site)) = item.website.as_deref().and_then(canonical_http_candidate) {
                catalog
                    .entry(target.clone())
                    .or_default()
                    .insert(CatalogCandidate { key, site });
            }
            catalog.entry(target).or_default();
        }
        Ok(catalog
            .into_iter()
            .map(|(target, candidates)| (target, candidates.into_iter().collect()))
            .collect())
    }

    fn service_catalog_labels(&self) -> Result<BTreeMap<CatalogTarget, String>, VaultError> {
        let payload = self.payload()?;
        let mut labels = BTreeMap::new();
        for item in &payload.items {
            labels.insert(
                CatalogTarget {
                    kind: ServiceItemKind::Login,
                    id: item.id,
                },
                item.title.clone(),
            );
        }
        for item in &payload.secrets {
            let summary = crate::SecretItemSummary::from(item);
            let target = summary
                .login_id
                .filter(|id| {
                    summary.is_passkey && payload.items.iter().any(|login| login.id == *id)
                })
                .map(|id| CatalogTarget {
                    kind: ServiceItemKind::Login,
                    id,
                })
                .unwrap_or(CatalogTarget {
                    kind: ServiceItemKind::Secret,
                    id: item.id,
                });
            labels.entry(target).or_insert_with(|| item.title.clone());
        }
        for item in &payload.ssh_items {
            labels.insert(
                CatalogTarget {
                    kind: ServiceItemKind::Ssh,
                    id: item.id,
                },
                item.title.clone(),
            );
        }
        for item in &payload.identities {
            labels.insert(
                CatalogTarget {
                    kind: ServiceItemKind::Identity,
                    id: item.id,
                },
                item.title.clone(),
            );
        }
        Ok(labels)
    }

    fn relationship_target_exists(&self, relationship: &ServiceRelationship) -> bool {
        self.payload()
            .is_ok_and(|payload| relationship_target_exists_in(payload, relationship))
    }

    fn valid_service_record(&self, service: &ServiceRecord) -> bool {
        !service.name.trim().is_empty()
            && !service.sites.is_empty()
            && service.relationships.iter().all(|relationship| {
                !service.relationships.iter().any(|other| {
                    !std::ptr::eq(relationship, other) && relationship.same_target(other)
                })
            })
    }

    fn service_summary(&self, service: &ServiceRecord) -> ServiceSummary {
        service_summary_with(
            |relationship| self.relationship_target_exists(relationship),
            service,
        )
    }

    fn push_service_history(
        &mut self,
        item: ServiceRecord,
        saved_at: u64,
    ) -> Result<(), VaultError> {
        let service_id = item.id;
        let payload = self.payload_mut()?;
        payload.service_history.push(ServiceRevision {
            revision_id: Uuid::new_v4(),
            service_id,
            saved_at,
            item,
        });
        let matching = payload
            .service_history
            .iter()
            .enumerate()
            .filter(|(_, revision)| revision.service_id == service_id)
            .map(|(index, revision)| (index, revision.saved_at))
            .collect::<Vec<_>>();
        if matching.len() > MAX_SERVICE_REVISIONS_PER_ITEM
            && let Some((oldest, _)) = matching.into_iter().min_by_key(|(_, saved_at)| *saved_at)
        {
            payload.service_history.remove(oldest);
        }
        Ok(())
    }
}

fn relationship_target_exists_in(
    payload: &crate::VaultPayload,
    relationship: &ServiceRelationship,
) -> bool {
    match relationship.item_kind {
        ServiceItemKind::Login => payload
            .items
            .iter()
            .any(|item| item.id == relationship.item_id),
        ServiceItemKind::Secret => payload
            .secrets
            .iter()
            .any(|item| item.id == relationship.item_id),
        ServiceItemKind::Ssh => payload
            .ssh_items
            .iter()
            .any(|item| item.id == relationship.item_id),
        ServiceItemKind::Identity => payload
            .identities
            .iter()
            .any(|item| item.id == relationship.item_id),
    }
}

pub(super) fn remove_service_relationships_in_payload(
    payload: &mut crate::VaultPayload,
    kind: ServiceItemKind,
    item_ids: &HashSet<Uuid>,
) {
    for service in &mut payload.services {
        service.relationships.retain(|relationship| {
            relationship.item_kind != kind || !item_ids.contains(&relationship.item_id)
        });
    }
    for trashed in &mut payload.service_trash {
        trashed.item.relationships.retain(|relationship| {
            relationship.item_kind != kind || !item_ids.contains(&relationship.item_id)
        });
    }
    payload
        .service_ignored_suggestions
        .retain(|ignored| ignored.item_kind != kind || !item_ids.contains(&ignored.item_id));
}

fn service_summary_with(
    valid: impl Fn(&ServiceRelationship) -> bool,
    service: &ServiceRecord,
) -> ServiceSummary {
    let mut counts = ServiceItemCounts::default();
    for relationship in service
        .relationships
        .iter()
        .filter(|relationship| valid(relationship))
    {
        counts.add(relationship.item_kind);
    }
    ServiceSummary {
        id: service.id,
        name: service.name.clone(),
        description: service.description.clone(),
        tags: service.tags.clone(),
        site_count: service.sites.len() as u32,
        counts,
        created_at: service.created_at,
        updated_at: service.updated_at,
    }
}

fn sort_relationships(relationships: &mut [ServiceRelationship]) {
    relationships.sort_by_key(|relationship| (relationship.item_kind, relationship.item_id));
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
