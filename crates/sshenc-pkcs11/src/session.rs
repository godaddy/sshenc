// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! PKCS#11 session management.

/// Manages PKCS#11 sessions with a simple handle allocation scheme.
pub struct SessionManager {
    /// Tracks which session handles are active.
    sessions: Vec<bool>,
    max_sessions: usize,
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        SessionManager {
            sessions: vec![false; max_sessions],
            max_sessions,
        }
    }

    /// Open a new session, returning its handle. Returns None if at capacity.
    pub fn open(&mut self) -> Option<u64> {
        for (i, active) in self.sessions.iter_mut().enumerate() {
            if !*active {
                *active = true;
                // Handles are 1-based (0 is invalid in PKCS#11)
                return Some((i + 1) as u64);
            }
        }
        None
    }

    /// Close a session by handle. Returns true if the session existed.
    pub fn close(&mut self, handle: u64) -> bool {
        let idx = handle as usize;
        if idx == 0 || idx > self.max_sessions {
            return false;
        }
        let slot = &mut self.sessions[idx - 1];
        if *slot {
            *slot = false;
            true
        } else {
            false
        }
    }

    /// Close all sessions.
    pub fn close_all(&mut self) {
        self.sessions.fill(false);
    }

    /// Check if a session handle is valid.
    pub fn is_valid(&self, handle: u64) -> bool {
        let idx = handle as usize;
        if idx == 0 || idx > self.max_sessions {
            return false;
        }
        self.sessions[idx - 1]
    }

    /// Return the number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.iter().filter(|&&a| a).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mut mgr = SessionManager::new(4);
        assert_eq!(mgr.active_count(), 0);

        let h1 = mgr.open().unwrap();
        let h2 = mgr.open().unwrap();
        assert_ne!(h1, h2);
        assert_eq!(mgr.active_count(), 2);

        assert!(mgr.is_valid(h1));
        assert!(mgr.is_valid(h2));
        assert!(!mgr.is_valid(0));
        assert!(!mgr.is_valid(99));

        assert!(mgr.close(h1));
        assert!(!mgr.is_valid(h1));
        assert_eq!(mgr.active_count(), 1);

        // Can reuse the slot
        let h3 = mgr.open().unwrap();
        assert_eq!(h3, h1); // reuses first available
        assert_eq!(mgr.active_count(), 2);
    }

    #[test]
    fn test_close_all() {
        let mut mgr = SessionManager::new(4);
        mgr.open();
        mgr.open();
        mgr.open();
        assert_eq!(mgr.active_count(), 3);

        mgr.close_all();
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_max_sessions() {
        let mut mgr = SessionManager::new(2);
        assert!(mgr.open().is_some());
        assert!(mgr.open().is_some());
        assert!(mgr.open().is_none()); // at capacity
    }

    #[test]
    fn test_close_invalid() {
        let mut mgr = SessionManager::new(4);
        assert!(!mgr.close(0));
        assert!(!mgr.close(1)); // not opened
        assert!(!mgr.close(99));
    }
}
