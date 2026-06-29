#![allow(dead_code)]

/// Messages sent from the daemon to the D-Bus UI layer.
#[derive(Debug, Clone)]
pub enum DaemonToUi {
    /// One or more unverified devices blocked a send in an E2E room.
    UnverifiedDevices {
        pan_user: String,
        room_id: String,
        room_display_name: String,
    },
    /// Remote device is inviting us to a SAS verification.
    SasInvite {
        pan_user: String,
        user_id: String,
        device_id: String,
        transaction_id: String,
    },
    /// SAS emoji/decimal codes are ready to display.
    SasShow {
        pan_user: String,
        user_id: String,
        device_id: String,
        transaction_id: String,
        emoji: Vec<(String, String)>,
    },
    /// SAS verification completed (success or cancel).
    SasDone {
        pan_user: String,
        user_id: String,
        device_id: String,
        transaction_id: String,
    },
    /// Result of a daemon operation requested by the UI.
    Response {
        message_id: String,
        pan_user: String,
        code: String,
        message: String,
    },
    /// A new user/device pair is now tracked by this server.
    UpdateUser {
        server: String,
        user_id: String,
        device_id: String,
    },
    /// Device list update for a pan_user.
    UpdateDevices {
        pan_user: String,
        devices: serde_json::Value,
    },
    /// A key-share request arrived — forwarded to the UI for user decision.
    KeyRequest {
        pan_user: String,
        event: serde_json::Value,
    },
}

/// Messages sent from the D-Bus UI layer to the daemon.
#[derive(Debug, Clone)]
pub enum UiToDaemon {
    // Unverified-devices gate responses
    SendAnyways {
        message_id: String,
        pan_user: String,
        room_id: String,
    },
    CancelSending {
        message_id: String,
        pan_user: String,
        room_id: String,
    },

    // Device trust management
    VerifyDevice {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },
    UnverifyDevice {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },
    BlacklistDevice {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },
    UnblacklistDevice {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    // Key import / export
    ImportKeys {
        message_id: String,
        pan_user: String,
        file_path: String,
        passphrase: String,
    },
    ExportKeys {
        message_id: String,
        pan_user: String,
        file_path: String,
        passphrase: String,
    },

    // SAS emoji verification
    StartSas {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },
    CancelSas {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },
    ConfirmSas {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },
    AcceptSas {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    // Key-share forwarding decisions
    ContinueKeyShare {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },
    CancelKeyShare {
        message_id: String,
        pan_user: String,
        user_id: String,
        device_id: String,
    },

    /// Restore cross-signing identity from the SSSS security key or passphrase.
    RecoverIdentity {
        message_id: String,
        pan_user: String,
        /// Raw input — either the Base58 recovery key or a passphrase.
        key_input: String,
    },
}

impl UiToDaemon {
    /// Extract the `pan_user` field present in every variant.
    pub fn pan_user(&self) -> &str {
        match self {
            UiToDaemon::SendAnyways { pan_user, .. }
            | UiToDaemon::CancelSending { pan_user, .. }
            | UiToDaemon::VerifyDevice { pan_user, .. }
            | UiToDaemon::UnverifyDevice { pan_user, .. }
            | UiToDaemon::BlacklistDevice { pan_user, .. }
            | UiToDaemon::UnblacklistDevice { pan_user, .. }
            | UiToDaemon::ImportKeys { pan_user, .. }
            | UiToDaemon::ExportKeys { pan_user, .. }
            | UiToDaemon::StartSas { pan_user, .. }
            | UiToDaemon::CancelSas { pan_user, .. }
            | UiToDaemon::ConfirmSas { pan_user, .. }
            | UiToDaemon::AcceptSas { pan_user, .. }
            | UiToDaemon::ContinueKeyShare { pan_user, .. }
            | UiToDaemon::CancelKeyShare { pan_user, .. }
            | UiToDaemon::RecoverIdentity { pan_user, .. } => pan_user,
        }
    }

    /// Extract the `message_id` field present in every variant.
    pub fn message_id(&self) -> &str {
        match self {
            UiToDaemon::SendAnyways { message_id, .. }
            | UiToDaemon::CancelSending { message_id, .. }
            | UiToDaemon::VerifyDevice { message_id, .. }
            | UiToDaemon::UnverifyDevice { message_id, .. }
            | UiToDaemon::BlacklistDevice { message_id, .. }
            | UiToDaemon::UnblacklistDevice { message_id, .. }
            | UiToDaemon::ImportKeys { message_id, .. }
            | UiToDaemon::ExportKeys { message_id, .. }
            | UiToDaemon::StartSas { message_id, .. }
            | UiToDaemon::CancelSas { message_id, .. }
            | UiToDaemon::ConfirmSas { message_id, .. }
            | UiToDaemon::AcceptSas { message_id, .. }
            | UiToDaemon::ContinueKeyShare { message_id, .. }
            | UiToDaemon::CancelKeyShare { message_id, .. }
            | UiToDaemon::RecoverIdentity { message_id, .. } => message_id,
        }
    }
}
