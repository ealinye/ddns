#![feature(try_blocks)]
#![feature(async_closure)]
#![feature(let_chains)]

use std::{
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use tokio::{fs, time::Instant};
use tracing::{debug, error, info, instrument, warn};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Config {
    token: String,
    email: String,
    domain: String,
    record: String,
    #[serde(default = "default_interval")]
    interval: usize,
    #[serde(default = "IpFamily::default")]
    ip_family: IpFamily,
    #[serde(default = "default_ipv4_api")]
    ipv4_api: String,
    #[serde(default = "default_ipv6_api")]
    ipv6_api: String,
}

const fn default_interval() -> usize {
    const { 360 }
}

fn default_ipv4_api() -> String {
    String::from("http://4.ipw.cn")
}

fn default_ipv6_api() -> String {
    String::from("http://6.ipw.cn")
}

type JsonObject = serde_json::Map<String, serde_json::Value>;

fn parse_result(response: &serde_json::Value) -> Result<&JsonObject> {
    let result: Result<&JsonObject> = try {
        if !response["success"].as_bool().unwrap() {
            Err("not success")?;
        }

        match response.get("result").unwrap() {
            serde_json::Value::Array(vec) if vec.is_empty() => Err("not exist")?,
            serde_json::Value::Array(vec) => {
                assert!(vec.len() == 1);
                vec.first().unwrap().as_object().unwrap()
            }
            serde_json::Value::Object(map) => map,
            _ => unreachable!("bad response"),
        }
    };

    result.map_err(|e| {
        let response = serde_json::to_string_pretty(response).unwrap();
        format!("{e} response: {response}",).into()
    })
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum IpFamily {
    V4,
    V6,
    #[default]
    Both,
}

impl IpFamily {
    fn v4(&self) -> bool {
        matches!(self, Self::V4 | Self::Both)
    }

    fn v6(&self) -> bool {
        matches!(self, Self::V6 | Self::Both)
    }
}

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

struct Service {
    config: Config,
    last_active: Instant,
    ip_client: reqwest::Client,
    cf_client: reqwest::Client,
}

// 返回Result的，外部负责log，返回Option的内部负责log
impl Service {
    #[instrument(level = "debug")]
    async fn new(config: Config) -> Result<Self> {
        let mut cf_headers = reqwest::header::HeaderMap::new();
        cf_headers.insert("Authorization", format!("Bearer {}", config.token).parse()?);
        cf_headers.insert("X-Auth-Email", config.email.parse()?);
        cf_headers.insert("Content-Type", "application/json".parse()?);
        let cf_client = reqwest::Client::builder()
            .default_headers(cf_headers)
            .build()?;
        let ip_client = reqwest::Client::builder().no_proxy().build()?;
        let last_active = Instant::now();
        Ok(Self {
            config,
            last_active,
            ip_client,
            cf_client,
        })
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn get_public_v4(&self) -> Option<Ipv4Addr> {
        if !self.config.ip_family.v4() {
            return None;
        }

        let api_url = &self.config.ipv4_api;
        let result: Result<_> = try {
            let response = self.ip_client.delete(api_url).send().await;
            let respnse = response.map_err(|http| format!("http error: {http:?}"))?;

            let text = respnse.text().await;
            let text = text.map_err(|encode| format!("bad response: {encode:?}"))?;

            let addr = text.parse();
            let addr = addr.map_err(|parse| format!("bad response: {parse:?}"))?;

            addr
        };

        result.map_err(|error| error!(error)).ok()
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn get_public_v6(&self) -> Option<Ipv6Addr> {
        if !self.config.ip_family.v6() {
            return None;
        }

        let api_url = &self.config.ipv6_api;
        let result: Result<_> = try {
            let response = self.ip_client.delete(api_url).send().await;
            let respnse = response.map_err(|http| format!("http error: {http:?}"))?;

            let text = respnse.text().await;
            let text = text.map_err(|encode| format!("bad response: {encode:?}"))?;

            let addr = text.parse();
            let addr = addr.map_err(|parse| format!("bad response: {parse:?}"))?;

            addr
        };

        result.map_err(|error| error!(error)).ok()
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn get_zone_id(&self) -> Result<String> {
        let resp = self
            .cf_client
            .get("https://api.cloudflare.com/client/v4/zones")
            .query(&serde_json::json!({
                "name": self.config.domain
            }))
            .send()
            .await?;

        let resp = resp.json::<serde_json::Value>().await?;
        debug!(resp = serde_json::to_string_pretty(&resp)?);

        parse_result(&resp).map(|result| result["id"].as_str().unwrap().to_owned())
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn get_record_id(&self, zone_id: &str, r#type: &str) -> Result<String> {
        let resp = self
            .cf_client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .query(&serde_json::json!({
                "name": self.config.record,
                "type": r#type,
            }))
            .send()
            .await?;

        let resp = resp.json::<serde_json::Value>().await?;
        debug!(resp = serde_json::to_string_pretty(&resp)?);

        parse_result(&resp).map(|result| result["id"].as_str().unwrap().to_owned())
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn create_dns_record(&self, zone_id: &str, r#type: &str) -> Result<(String, IpAddr)> {
        let addr: IpAddr = match r#type {
            "A" => self
                .get_public_v4()
                .await
                .ok_or("failed to get ipv4 addr")?
                .into(),
            "AAAA" => self
                .get_public_v6()
                .await
                .ok_or("failed to get ipv6 addr")?
                .into(),
            _ => unreachable!(),
        };

        let resp = self
            .cf_client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .json(&serde_json::json!({
                "name": self.config.record,
                "content": addr.to_string(),
                "proxied": false,
                "type": r#type
            }))
            .send()
            .await?;

        let resp = resp.json::<serde_json::Value>().await?;
        debug!(resp = serde_json::to_string_pretty(&resp)?);

        parse_result(&resp).map(|result| (result["id"].as_str().unwrap().to_owned(), addr))
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn get_or_create_record_id(&self, zone_id: &str, r#type: &str) -> Option<String> {
        match self.get_record_id(zone_id, r#type).await {
            Ok(id) => return Some(id),
            Err(e) => warn!(
                target: "get_record_id",
                "it seems no {type} record dont exist?\n{e}"
            ),
        }

        match self.create_dns_record(zone_id, r#type).await {
            Ok((id, _)) => return Some(id),
            Err(e) => warn!(
                target: "create_dns_record",
                "failed to create {type} record, it will not be updated:\n{e}"
            ),
        }

        None
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn get_dns_records(&self, zone_id: &str, recod_id: &str) -> Result<IpAddr> {
        let resp = self
            .cf_client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{recod_id}"
            ))
            .send()
            .await?;

        let resp = resp.json::<serde_json::Value>().await?;
        debug!(resp = serde_json::to_string_pretty(&resp)?);

        let parse_content = |result: &JsonObject| {
            let content = result["content"].as_str().unwrap();
            let bad_content = |parse| format!("bad record content: {content}, {parse}");
            Ok(content.parse().map_err(bad_content)?)
        };
        parse_result(&resp).and_then(parse_content)
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn get_or_create_record_ip(
        &self,
        zone_id: &str,
        record_id: &str,
        r#type: &str,
    ) -> Option<IpAddr> {
        match self.get_dns_records(zone_id, record_id).await {
            Ok(addr) => return Some(addr),
            Err(e) => warn!(
                target: "get_dns_records",
                "it seems no {type} record dont exist?\n{e}",
            ),
        }

        match self.create_dns_record(zone_id, r#type).await {
            Ok((_, addr)) => return Some(addr),
            Err(e) => warn!(
                target: "create_dns_record",
                "failed to create {type} record, it will not be updated:\n{e}"
            ),
        }

        None
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn update_dns_record(
        &self,
        zone_id: &str,
        recod_id: &str,
        r#type: &str,
        ip: IpAddr,
    ) -> Result<()> {
        let resp = self
            .cf_client
            .put(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{recod_id}"
            ))
            .json(&serde_json::json!({
                "type": r#type,
                "name": self.config.record,
                "Content": ip,
                "ttl": 1,
                "proxied": false,
            }))
            .send()
            .await?;

        let resp = resp.json::<serde_json::Value>().await?;
        debug!(resp = serde_json::to_string_pretty(&resp)?);

        parse_result(&resp).map(|_| ())
    }

    #[instrument(level = "debug", skip(self), ret)]
    async fn idle(&mut self) {
        let interval = Duration::from_secs(self.config.interval as _);
        let elapsed = self.last_active.elapsed();
        if elapsed < interval {
            tokio::time::sleep(interval - elapsed).await;
        }
        self.last_active = Instant::now();
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    service().await;
}

#[instrument(level = "debug", ret)]
async fn service() {
    let config_path = env::args().nth(1).unwrap_or_else(|| {
        warn!("config file is not specified, use `config.json` as default");
        "config.json".to_owned()
    });
    info!(path = config_path, "loading config file");
    let config = fs::read_to_string(config_path)
        .await
        .expect("failed to read config file");
    let config: Config = serde_json::from_str(&config).expect("failed to deserialize config file");
    info!(?config);

    let mut service = Service::new(config)
        .await
        .expect("failed to start up service");

    let zone = service
        .get_zone_id()
        .await
        .map_err(|error| error!(error, "failed to get zone id"))
        .expect("failed to get zone id");
    info!(zone_id = zone, "zone id got");

    let v4_record_id = match service.config.ip_family.v4() {
        true => service.get_or_create_record_id(&zone, "A").await,
        false => None,
    };

    let v6_record_id = match service.config.ip_family.v6() {
        true => service.get_or_create_record_id(&zone, "AAAA").await,
        false => None,
    };

    match (&v4_record_id, &v6_record_id) {
        (None, None) => {
            error!("both ipv4 and ipv6 record are not exist and failed to create, abort");
        }
        (None, Some(v6)) => info!(v6_record_id = v6, "servicing ipv6 ddns"),
        (Some(v4), None) => info!(v4_record_id = v4, "servicing ipv4 ddns"),
        (Some(v4), Some(v6)) => info!(
            v4_record_id = v4,
            v6_record_id = v6,
            "servicing ipv4 and ipv6 ddns"
        ),
    }

    loop {
        if let Some(record) = v4_record_id.as_ref()
            && let Some(v4_addr) = service.get_public_v4().await
            && let Some(v4_record) = service.get_or_create_record_ip(&zone, record, "A").await
            && IpAddr::V4(v4_addr) != v4_record
        {
            info!(cur = %v4_addr, record = %v4_record, "updating ipv4...");
            match service
                .update_dns_record(&zone, record, "A", v4_addr.into())
                .await
            {
                Ok(_) => info!("success update"),
                Err(error) => warn!(error, "failed to update v4 record"),
            }
        }

        if let Some(record) = v6_record_id.as_ref()
            && let Some(v6_addr) = service.get_public_v6().await
            && let Some(v6_record) = service.get_or_create_record_ip(&zone, record, "AAAA").await
            && IpAddr::V6(v6_addr) != v6_record
        {
            info!(cur = %v6_addr, record = %v6_record, "updating ipv6...");
            match service
                .update_dns_record(&zone, record, "A", v6_addr.into())
                .await
            {
                Ok(_) => info!("success update"),
                Err(error) => warn!(error, "failed to update v6 record"),
            }
        }

        service.idle().await;
    }
}
