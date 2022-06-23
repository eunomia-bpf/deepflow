use std::sync::Arc;

use bincode::{Decode, Encode};
use parking_lot::RwLock;
use tokio::runtime::Runtime;

use super::error::{Error, Result};

use crate::config::RuntimeConfig;
use crate::exception::ExceptionHandler;
use crate::proto::trident::{self, SyncResponse};
use crate::rpc::{Session, StaticConfig, Status, Synchronizer};

pub struct RpcDebugger {
    session: Arc<Session>,
    status: Arc<RwLock<Status>>,
    config: Arc<StaticConfig>,
    rt: Runtime,
}

#[derive(PartialEq, Debug)]
pub struct ConfigResp {
    status: i32,
    version_platform_data: u64,
    version_acls: u64,
    version_groups: u64,
    revision: String,
    config: String,
    self_update_url: String,
}

#[derive(PartialEq, Debug, Encode, Decode)]
pub enum RpcMessage {
    Config(Option<String>),
    PlatformData(Option<String>),
    TapTypes(Option<String>),
    Cidr(Option<String>),
    Groups(Option<String>),
    Acls(Option<String>),
    Segments(Option<String>),
    Version(Option<String>),
    Err(String),
    Fin,
}

impl RpcDebugger {
    pub(super) fn new(
        session: Arc<Session>,
        config: Arc<StaticConfig>,
        status: Arc<RwLock<Status>>,
    ) -> Self {
        Self {
            session,
            status,
            config,
            rt: Runtime::new().unwrap(),
        }
    }

    async fn get_rpc_response(&self) -> Result<tonic::Response<SyncResponse>, tonic::Status> {
        let exception_handler = ExceptionHandler::default();
        let req =
            Synchronizer::generate_sync_request(&self.config, &self.status, 0, &exception_handler);
        self.session.update_current_server().await;

        let client = self
            .session
            .get_client()
            .ok_or(tonic::Status::not_found("rpc client not connected"))?;

        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);
        let resp = client.sync(req).await?;
        Ok(resp)
    }

    pub(super) fn basic_config(&self) -> Result<Vec<RpcMessage>> {
        let mut resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.config.is_none() {
            return Err(Error::NotFound(String::from(
                "sync response's config is empty",
            )));
        }

        let c = RuntimeConfig::try_from(resp.config.take().unwrap())?;
        let config = ConfigResp {
            status: resp.status() as i32,
            version_platform_data: resp.version_platform_data(),
            version_groups: resp.version_groups(),
            revision: resp.revision.take().unwrap_or_default(),
            config: format!("{:?}", c),
            version_acls: resp.version_acls(),
            self_update_url: resp.self_update_url.take().unwrap_or_default(),
        };

        let c = format!("{:?}", config);

        Ok(vec![RpcMessage::Config(Some(c)), RpcMessage::Fin])
    }

    pub(super) fn tap_types(&self) -> Result<Vec<RpcMessage>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.tap_types.is_empty() {
            return Err(Error::NotFound(String::from(
                "sync response's tap_types is empty",
            )));
        }

        let mut res = resp
            .tap_types
            .into_iter()
            .map(|t| RpcMessage::TapTypes(Some(format!("{:?}", t))))
            .collect::<Vec<_>>();

        res.push(RpcMessage::Fin);
        Ok(res)
    }

    pub(super) fn cidrs(&self) -> Result<Vec<RpcMessage>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_platform_data() == 0 {
            return Err(Error::NotFound(String::from("cidrs data in preparation")));
        }

        self.status.write().get_platform_data(&resp);
        let mut res = self
            .status
            .read()
            .cidrs
            .iter()
            .map(|c| RpcMessage::Cidr(Some(format!("{:?}", c))))
            .collect::<Vec<_>>();

        res.push(RpcMessage::Fin);
        Ok(res)
    }

    pub(super) fn platform_data(&self) -> Result<Vec<RpcMessage>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_platform_data() == 0 {
            return Err(Error::NotFound(String::from(
                "platform data in preparation",
            )));
        }

        self.status.write().get_platform_data(&resp);
        let mut res = {
            let status_guard = self.status.read();
            status_guard
                .interfaces
                .iter()
                .map(|p| RpcMessage::PlatformData(Some(format!("{:?}", p))))
                .chain(
                    status_guard
                        .peers
                        .iter()
                        .map(|p| RpcMessage::PlatformData(Some(format!("{:?}", p)))),
                )
                .collect::<Vec<_>>()
        };

        res.push(RpcMessage::Fin);
        Ok(res)
    }

    pub(super) fn ip_groups(&self) -> Result<Vec<RpcMessage>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_groups() == 0 {
            return Err(Error::NotFound(String::from(
                "ip groups data in preparation",
            )));
        }

        self.status.write().get_ip_groups(&resp);
        let mut res = self
            .status
            .read()
            .ip_groups
            .iter()
            .map(|g| RpcMessage::Groups(Some(format!("{:?}", g))))
            .collect::<Vec<_>>();

        res.push(RpcMessage::Fin);
        Ok(res)
    }

    pub(super) fn flow_acls(&self) -> Result<Vec<RpcMessage>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_acls() == 0 {
            return Err(Error::NotFound(String::from(
                "flow acls data in preparation",
            )));
        }

        self.status.write().get_flow_acls(&resp);
        let mut res = self
            .status
            .read()
            .acls
            .iter()
            .map(|a| RpcMessage::Acls(Some(format!("{:?}", a))))
            .collect::<Vec<_>>();

        res.push(RpcMessage::Fin);
        Ok(res)
    }

    pub(super) fn local_segments(&self) -> Result<Vec<RpcMessage>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.local_segments.is_empty() {
            return Err(Error::NotFound(
                "local segments data is empty, maybe metaflow-agent is not properly configured"
                    .into(),
            ));
        }

        let mut segments = resp
            .local_segments
            .into_iter()
            .map(|s| RpcMessage::Segments(Some(format!("{:?}", s))))
            .collect::<Vec<_>>();

        segments.push(RpcMessage::Fin);

        Ok(segments)
    }

    pub(super) fn current_version(&self) -> Result<Vec<RpcMessage>> {
        let status = self.status.read();
        let version = format!(
            "platformData version: {}\n groups version: {}\nflowAcls version: {}",
            status.version_platform_data, status.version_groups, status.version_acls
        );

        Ok(vec![RpcMessage::Version(Some(version)), RpcMessage::Fin])
    }
}