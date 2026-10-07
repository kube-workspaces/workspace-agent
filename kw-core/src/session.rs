//! Session and display-seat ownership.
//!
//! First milestone is exclusive-controller only: one authoritative
//! seat/session claim per media/control socket group. Observers arrive later
//! with view-only enforcement — the seat model already reserves that shape.

use kw_protocol::{admit_ticket, Scope, Ticket};

/// Participant role. Only [`Role::Controller`] exists in milestone one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Controller,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Controller => "controller",
        }
    }
}

/// Exclusive display seat: who holds input, and at which control epoch.
#[derive(Debug)]
pub struct Session {
    session_id: String,
    generation: u64,
    /// Current control epoch. Tickers below this are fenced.
    control_epoch: u64,
    holder: Option<String>,
}

impl Session {
    pub fn new(session_id: String, generation: u64) -> Self {
        Self {
            session_id,
            generation,
            control_epoch: 0,
            holder: None,
        }
    }

    /// Attach with a ticket. Only the controller role exists yet; anything
    /// else is rejected without a silent fallback.
    pub fn attach(
        &mut self,
        ticket: &Ticket,
        workspace_uid: &str,
        now_ns: u64,
    ) -> Result<Role, kw_protocol::Reject> {
        let scope = Scope {
            workspace_uid,
            session_id: &self.session_id,
            audience: "workspace-agent",
            min_control_epoch: self.control_epoch,
        };
        admit_ticket(ticket, &scope, now_ns)?;
        if ticket.role != Role::Controller.as_str() {
            return Err(kw_protocol::Reject::Ticket);
        }
        self.control_epoch = self.control_epoch.max(ticket.control_epoch);
        self.holder = Some(ticket.participant.clone());
        Ok(Role::Controller)
    }

    /// Release held input: disconnect, focus loss, epoch change, teardown.
    /// Idempotent; never fails.
    pub fn release(&mut self) {
        self.holder = None;
    }

    pub fn holder(&self) -> Option<&str> {
        self.holder.as_deref()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(role: &str, epoch: u64, expires: u64) -> Ticket {
        Ticket {
            workspace_uid: "ws".into(),
            workspace_generation: "gen".into(),
            session_id: "sess".into(),
            participant: "c1".into(),
            role: role.into(),
            control_epoch: epoch,
            audience: "workspace-agent".into(),
            expires_at_ns: expires,
        }
    }

    #[test]
    fn controller_attaches_and_releases() {
        let mut session = Session::new("sess".into(), 7);
        assert!(session
            .attach(&ticket("controller", 1, 500), "ws", 100)
            .is_ok());
        assert_eq!(session.holder(), Some("c1"));
        session.release();
        assert_eq!(session.holder(), None);
        // Release is idempotent.
        session.release();
    }

    #[test]
    fn observer_role_rejected_without_fallback() {
        let mut session = Session::new("sess".into(), 7);
        assert!(session
            .attach(&ticket("observer", 1, 500), "ws", 100)
            .is_err());
        assert_eq!(session.holder(), None);
    }

    #[test]
    fn demotion_fences_old_ticket() {
        let mut session = Session::new("sess".into(), 7);
        assert!(session
            .attach(&ticket("controller", 5, 500), "ws", 100)
            .is_ok());
        // An older epoch no longer admits, even unexpired.
        assert!(session
            .attach(&ticket("controller", 4, 500), "ws", 100)
            .is_err());
    }
}
