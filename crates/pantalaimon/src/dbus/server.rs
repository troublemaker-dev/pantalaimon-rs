use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::{
    messages::{DaemonToUi, UiToDaemon},
    proxy::daemon::ProxyDaemon,
};

/// D-Bus interface server, exposing `org.pantalaimon1` on the session bus.
///
/// When the `ui` feature is disabled (default), the server is a no-op that
/// drains the signal channel to prevent backpressure.
#[allow(dead_code)]
pub struct DbusServer {
    pan_tx: mpsc::Sender<UiToDaemon>,
    ui_rx: mpsc::Receiver<DaemonToUi>,
    daemons: Arc<DashMap<String, Arc<ProxyDaemon>>>,
}

impl DbusServer {
    pub fn new(
        pan_tx: mpsc::Sender<UiToDaemon>,
        ui_rx: mpsc::Receiver<DaemonToUi>,
        daemons: Arc<DashMap<String, Arc<ProxyDaemon>>>,
    ) -> Self {
        Self { pan_tx, ui_rx, daemons }
    }

    pub async fn run(self) {
        #[cfg(feature = "ui")]
        {
            if let Err(e) = run_ui(self.pan_tx, self.ui_rx, self.daemons).await {
                tracing::warn!("D-Bus server exited: {e:#}");
            }
        }
        #[cfg(not(feature = "ui"))]
        {
            tracing::debug!("D-Bus UI not enabled; draining signal channel");
            let mut rx = self.ui_rx;
            while rx.recv().await.is_some() {}
        }
    }
}

// ---------------------------------------------------------------------------
// UI feature — full zbus implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "ui")]
async fn run_ui(
    pan_tx: mpsc::Sender<UiToDaemon>,
    mut ui_rx: mpsc::Receiver<DaemonToUi>,
    daemons: Arc<DashMap<String, Arc<ProxyDaemon>>>,
) -> zbus::Result<()> {
    use std::sync::{
        atomic::AtomicU32,
        Arc as SArc,
    };

    let state = SArc::new(SharedState {
        pan_tx,
        daemons,
        next_id: SArc::new(AtomicU32::new(1)),
    });

    let ctrl = ControlIface { state: state.clone() };
    let devs = DevicesIface { state };

    let conn = zbus::connection::Builder::session()?
        .name("org.pantalaimon1")?
        .serve_at("/org/pantalaimon1", ctrl)?
        .serve_at("/org/pantalaimon1", devs)?
        .build()
        .await?;

    let obj = conn.object_server();
    let ctrl_ref = obj.interface::<_, ControlIface>("/org/pantalaimon1").await?;
    let devs_ref = obj.interface::<_, DevicesIface>("/org/pantalaimon1").await?;
    // Clone the signal contexts once so the background loop can emit without
    // re-borrowing the InterfaceRef on each iteration.
    let ctrl_ctx = ctrl_ref.signal_context().clone();
    let devs_ctx = devs_ref.signal_context().clone();

    tracing::info!("D-Bus interface published at org.pantalaimon1 /org/pantalaimon1");

    while let Some(ev) = ui_rx.recv().await {
        emit_signal(&ctrl_ref, &devs_ref, &ctrl_ctx, &devs_ctx, ev).await;
    }

    Ok(())
}

#[cfg(feature = "ui")]
async fn emit_signal(
    ctrl_ref: &zbus::InterfaceRef<ControlIface>,
    devs_ref: &zbus::InterfaceRef<DevicesIface>,
    ctrl_ctx: &zbus::SignalContext<'_>,
    devs_ctx: &zbus::SignalContext<'_>,
    ev: DaemonToUi,
) {
    let r: zbus::Result<()> = match ev {
        DaemonToUi::UnverifiedDevices { pan_user, room_id, room_display_name } => {
            ctrl_ref
                .get()
                .await
                .unverified_devices(ctrl_ctx, &pan_user, &room_id, &room_display_name)
                .await
        }
        DaemonToUi::SasInvite { pan_user, user_id, device_id, transaction_id } => {
            ctrl_ref
                .get()
                .await
                .sas_invite(ctrl_ctx, &pan_user, &user_id, &device_id, &transaction_id)
                .await
        }
        DaemonToUi::SasShow { pan_user, user_id, device_id, transaction_id, emoji } => {
            ctrl_ref
                .get()
                .await
                .sas_show(ctrl_ctx, &pan_user, &user_id, &device_id, &transaction_id, emoji)
                .await
        }
        DaemonToUi::SasDone { pan_user, user_id, device_id, transaction_id } => {
            ctrl_ref
                .get()
                .await
                .sas_done(ctrl_ctx, &pan_user, &user_id, &device_id, &transaction_id)
                .await
        }
        DaemonToUi::Response { message_id, pan_user, code, message } => {
            ctrl_ref
                .get()
                .await
                .response(ctrl_ctx, &message_id, &pan_user, &code, &message)
                .await
        }
        DaemonToUi::UpdateUser { server, user_id, device_id } => {
            ctrl_ref
                .get()
                .await
                .update_user(ctrl_ctx, &server, &user_id, &device_id)
                .await
        }
        DaemonToUi::UpdateDevices { pan_user, devices } => {
            devs_ref
                .get()
                .await
                .update_devices(devs_ctx, &pan_user, &devices.to_string())
                .await
        }
        DaemonToUi::KeyRequest { .. } => Ok(()),
    };
    if let Err(e) = r {
        tracing::warn!("D-Bus signal emit failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Shared state for both interface objects
// ---------------------------------------------------------------------------

#[cfg(feature = "ui")]
struct SharedState {
    pan_tx: mpsc::Sender<UiToDaemon>,
    daemons: Arc<DashMap<String, Arc<ProxyDaemon>>>,
    next_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

#[cfg(feature = "ui")]
impl SharedState {
    fn next_id(&self) -> String {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_string()
    }

    fn find_client(&self, pan_user: &str) -> Option<Arc<crate::client::PanClient>> {
        for daemon in self.daemons.iter() {
            if let Some(client) = daemon.pan_clients.get(pan_user) {
                return Some(client.clone());
            }
        }
        None
    }

    async fn send(&self, cmd: UiToDaemon) {
        if self.pan_tx.send(cmd).await.is_err() {
            tracing::warn!("D-Bus: pan_tx channel closed");
        }
    }
}

// ---------------------------------------------------------------------------
// org.pantalaimon1.control interface
// ---------------------------------------------------------------------------

#[cfg(feature = "ui")]
struct ControlIface {
    state: std::sync::Arc<SharedState>,
}

#[cfg(feature = "ui")]
#[zbus::interface(name = "org.pantalaimon1.control")]
impl ControlIface {
    // Methods

    async fn list_servers(&self) -> Vec<std::collections::HashMap<String, String>> {
        self.state
            .daemons
            .iter()
            .map(|e| {
                let c = &e.server_conf;
                std::collections::HashMap::from([
                    ("name".to_owned(), c.name.clone()),
                    ("homeserver".to_owned(), c.homeserver.to_string()),
                    ("listen_address".to_owned(), c.listen_address.to_string()),
                    ("listen_port".to_owned(), c.listen_port.to_string()),
                ])
            })
            .collect()
    }

    async fn list_users(&self) -> Vec<String> {
        let mut users = Vec::new();
        for daemon in self.state.daemons.iter() {
            for entry in daemon.pan_clients.iter() {
                users.push(entry.key().clone());
            }
        }
        users.sort_unstable();
        users.dedup();
        users
    }

    async fn send_anyways(&self, pan_user: String, message_id: String, room_id: String) {
        self.state
            .send(UiToDaemon::SendAnyways { message_id, pan_user, room_id })
            .await;
    }

    async fn cancel_sending(&self, pan_user: String, message_id: String, room_id: String) {
        self.state
            .send(UiToDaemon::CancelSending { message_id, pan_user, room_id })
            .await;
    }

    async fn start_sas(&self, pan_user: String, user_id: String, device_id: String) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::StartSas {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn accept_sas(&self, pan_user: String, user_id: String, device_id: String) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::AcceptSas {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn confirm_sas(&self, pan_user: String, user_id: String, device_id: String) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::ConfirmSas {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn cancel_sas(&self, pan_user: String, user_id: String, device_id: String) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::CancelSas {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn import_keys(
        &self,
        pan_user: String,
        file_path: String,
        passphrase: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::ImportKeys {
                message_id: message_id.clone(),
                pan_user,
                file_path,
                passphrase,
            })
            .await;
        message_id
    }

    async fn export_keys(
        &self,
        pan_user: String,
        file_path: String,
        passphrase: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::ExportKeys {
                message_id: message_id.clone(),
                pan_user,
                file_path,
                passphrase,
            })
            .await;
        message_id
    }

    async fn recover_identity(&self, pan_user: String, key_input: String) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::RecoverIdentity {
                message_id: message_id.clone(),
                pan_user,
                key_input,
            })
            .await;
        message_id
    }

    async fn continue_key_share(
        &self,
        pan_user: String,
        user_id: String,
        device_id: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::ContinueKeyShare {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn cancel_key_share(
        &self,
        pan_user: String,
        user_id: String,
        device_id: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::CancelKeyShare {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    // Signals

    #[zbus(signal)]
    async fn response(
        &self,
        ctxt: &zbus::SignalContext<'_>,
        message_id: &str,
        pan_user: &str,
        code: &str,
        message: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn unverified_devices(
        &self,
        ctxt: &zbus::SignalContext<'_>,
        pan_user: &str,
        room_id: &str,
        room_display_name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn sas_invite(
        &self,
        ctxt: &zbus::SignalContext<'_>,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
        transaction_id: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn sas_show(
        &self,
        ctxt: &zbus::SignalContext<'_>,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
        transaction_id: &str,
        emoji: Vec<(String, String)>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn sas_done(
        &self,
        ctxt: &zbus::SignalContext<'_>,
        pan_user: &str,
        user_id: &str,
        device_id: &str,
        transaction_id: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn update_user(
        &self,
        ctxt: &zbus::SignalContext<'_>,
        server: &str,
        user_id: &str,
        device_id: &str,
    ) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// org.pantalaimon1.devices interface
// ---------------------------------------------------------------------------

#[cfg(feature = "ui")]
struct DevicesIface {
    state: std::sync::Arc<SharedState>,
}

#[cfg(feature = "ui")]
#[zbus::interface(name = "org.pantalaimon1.devices")]
impl DevicesIface {
    // Methods

    async fn list_devices(
        &self,
        pan_user: String,
        user_id: String,
    ) -> Vec<std::collections::HashMap<String, String>> {
        match self.state.find_client(&pan_user) {
            Some(client) => client.list_user_devices(&user_id).await,
            None => Vec::new(),
        }
    }

    async fn verify_device(
        &self,
        pan_user: String,
        user_id: String,
        device_id: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::VerifyDevice {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn unverify_device(
        &self,
        pan_user: String,
        user_id: String,
        device_id: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::UnverifyDevice {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn blacklist_device(
        &self,
        pan_user: String,
        user_id: String,
        device_id: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::BlacklistDevice {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    async fn unblacklist_device(
        &self,
        pan_user: String,
        user_id: String,
        device_id: String,
    ) -> String {
        let message_id = self.state.next_id();
        self.state
            .send(UiToDaemon::UnblacklistDevice {
                message_id: message_id.clone(),
                pan_user,
                user_id,
                device_id,
            })
            .await;
        message_id
    }

    // Signal

    #[zbus(signal)]
    async fn update_devices(
        &self,
        ctxt: &zbus::SignalContext<'_>,
        pan_user: &str,
        devices_json: &str,
    ) -> zbus::Result<()>;
}
