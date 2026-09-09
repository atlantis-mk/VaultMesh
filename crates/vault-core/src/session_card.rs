use super::*;

impl VaultSession {
    pub fn add_card(
        &mut self,
        input: NewPaymentCardItem,
    ) -> Result<PaymentCardSummary, VaultError> {
        let item = input.into_payment_card()?;
        let summary = PaymentCardSummary::from(&item);
        self.payload_mut()?.cards.push(item);
        Ok(summary)
    }

    pub fn update_card(
        &mut self,
        mut update: PaymentCardItemUpdate,
    ) -> Result<PaymentCardSummary, VaultError> {
        let normalized_number = update
            .card_number
            .as_deref()
            .map(crate::model::normalize_card_number)
            .transpose()?;
        crate::model::validate_card_fields(
            update.expiration_month,
            update.expiration_year,
            update.security_code.as_deref(),
            update.pin.as_deref(),
        )?;
        let item_index = self
            .payload()?
            .cards
            .iter()
            .position(|item| item.id == update.id)
            .ok_or(VaultError::ItemNotFound)?;
        let previous = self.payload()?.cards[item_index].clone();
        self.push_card_history(previous, unix_time_now())?;
        let item = &mut self.payload_mut()?.cards[item_index];

        item.title.zeroize();
        item.title = std::mem::take(&mut update.title);
        item.cardholder_name.zeroize();
        item.cardholder_name = std::mem::take(&mut update.cardholder_name);
        if let Some(mut number) = normalized_number {
            item.card_number.zeroize();
            item.card_number = std::mem::take(&mut number);
        }
        item.expiration_month = update.expiration_month;
        item.expiration_year = update.expiration_year;
        if update.clear_security_code {
            zeroize_option(&mut item.security_code);
            item.security_code = None;
        } else if let Some(mut code) = update.security_code.take() {
            zeroize_option(&mut item.security_code);
            item.security_code = Some(std::mem::take(&mut code));
        }
        if update.clear_pin {
            zeroize_option(&mut item.pin);
            item.pin = None;
        } else if let Some(mut pin) = update.pin.take() {
            zeroize_option(&mut item.pin);
            item.pin = Some(std::mem::take(&mut pin));
        }
        zeroize_option(&mut item.issuer);
        item.issuer = update.issuer.take();
        zeroize_option(&mut item.network);
        item.network = update.network.take();
        zeroize_option(&mut item.billing_address);
        item.billing_address = update.billing_address.take();
        zeroize_option(&mut item.notes);
        item.notes = update.notes.take();
        zeroize_option(&mut item.folder);
        item.folder = update.folder.take();
        item.favorite = update.favorite;
        item.master_password_reprompt = update.master_password_reprompt;

        Ok(PaymentCardSummary::from(&*item))
    }

    pub fn delete_card(&mut self, id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .cards
            .iter()
            .position(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        let item = payload.cards.remove(index);
        payload.card_trash.push(TrashedPaymentCard {
            trash_id: Uuid::new_v4(),
            deleted_at: unix_time_now(),
            item,
        });
        Ok(())
    }

    pub fn list_card_trash(&self) -> Result<Vec<PaymentCardTrashSummary>, VaultError> {
        Ok(self
            .payload()?
            .card_trash
            .iter()
            .map(PaymentCardTrashSummary::from)
            .collect())
    }

    pub fn restore_card_trash(&mut self, trash_id: Uuid) -> Result<PaymentCardSummary, VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .card_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let entry = payload.card_trash.remove(index);
        let item = entry.item.clone();
        let summary = PaymentCardSummary::from(&item);
        payload.cards.push(item);
        Ok(summary)
    }

    pub fn purge_card_trash(&mut self, trash_id: Uuid) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let index = payload
            .card_trash
            .iter()
            .position(|entry| entry.trash_id == trash_id)
            .ok_or(VaultError::TrashItemNotFound)?;
        let item_id = payload.card_trash[index].item.id;
        payload.card_trash.remove(index);
        payload
            .card_history
            .retain(|revision| revision.item_id != item_id);
        Ok(())
    }

    pub fn empty_card_trash(&mut self) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        let trashed_ids: HashSet<_> = payload
            .card_trash
            .iter()
            .map(|entry| entry.item.id)
            .collect();
        payload.card_trash.clear();
        payload
            .card_history
            .retain(|revision| !trashed_ids.contains(&revision.item_id));
        Ok(())
    }

    pub fn card_history(
        &self,
        item_id: Uuid,
    ) -> Result<Vec<PaymentCardRevisionSummary>, VaultError> {
        if !self.payload()?.cards.iter().any(|item| item.id == item_id) {
            return Err(VaultError::ItemNotFound);
        }
        let mut revisions: Vec<_> = self
            .payload()?
            .card_history
            .iter()
            .filter(|revision| revision.item_id == item_id)
            .map(PaymentCardRevisionSummary::from)
            .collect();
        revisions.sort_by_key(|revision| std::cmp::Reverse(revision.saved_at));
        Ok(revisions)
    }

    pub fn restore_card_revision(
        &mut self,
        item_id: Uuid,
        revision_id: Uuid,
    ) -> Result<PaymentCardSummary, VaultError> {
        let payload = self.payload()?;
        let item_index = payload
            .cards
            .iter()
            .position(|item| item.id == item_id)
            .ok_or(VaultError::ItemNotFound)?;
        let revision = payload
            .card_history
            .iter()
            .find(|revision| revision.item_id == item_id && revision.revision_id == revision_id)
            .ok_or(VaultError::RevisionNotFound)?
            .item
            .clone();
        let current = payload.cards[item_index].clone();
        self.push_card_history(current, unix_time_now())?;
        let item = &mut self.payload_mut()?.cards[item_index];
        item.zeroize();
        *item = revision;
        Ok(PaymentCardSummary::from(&*item))
    }

    pub fn clear_card_history(&mut self, item_id: Uuid) -> Result<(), VaultError> {
        if !self.payload()?.cards.iter().any(|item| item.id == item_id) {
            return Err(VaultError::ItemNotFound);
        }
        crate::sync::record_history_clear(self.payload_mut()?, "card_history", item_id)?;
        self.payload_mut()?
            .card_history
            .retain(|revision| revision.item_id != item_id);
        Ok(())
    }

    pub fn list_cards(&self) -> Result<Vec<PaymentCardSummary>, VaultError> {
        Ok(self
            .payload()?
            .cards
            .iter()
            .map(PaymentCardSummary::from)
            .collect())
    }

    pub fn card_detail(&self, id: Uuid) -> Result<PaymentCardDetail, VaultError> {
        self.payload()?
            .cards
            .iter()
            .find(|item| item.id == id)
            .map(PaymentCardDetail::from)
            .ok_or(VaultError::ItemNotFound)
    }

    pub fn card_number_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&str, VaultError> {
        let item = self.card_for_access(id, master_password)?;
        Ok(item.card_number.as_str())
    }

    /// Compares a submitted card number inside the unlocked core without
    /// disclosing the stored number or bypassing re-prompt for value access.
    pub fn card_number_matches(&self, id: Uuid, candidate: &str) -> Result<bool, VaultError> {
        let item = self
            .payload()?
            .cards
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        Ok(item.card_number == candidate)
    }

    /// A missing submitted security code means the form did not expose that
    /// field, so it preserves the stored code and is considered unchanged.
    pub fn card_security_code_matches(
        &self,
        id: Uuid,
        candidate: Option<&str>,
    ) -> Result<bool, VaultError> {
        let item = self
            .payload()?
            .cards
            .iter()
            .find(|item| item.id == id)
            .ok_or(VaultError::ItemNotFound)?;
        Ok(candidate.is_none_or(|value| item.security_code.as_deref() == Some(value)))
    }

    pub fn card_security_code_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&str, VaultError> {
        let item = self.card_for_access(id, master_password)?;
        item.security_code
            .as_deref()
            .ok_or(VaultError::CardSecretUnavailable)
    }

    pub fn card_pin_for_access(
        &self,
        id: Uuid,
        master_password: Option<&str>,
    ) -> Result<&str, VaultError> {
        let item = self.card_for_access(id, master_password)?;
        item.pin.as_deref().ok_or(VaultError::CardSecretUnavailable)
    }
}
