#![feature(try_blocks)]
#![feature(async_closure)]
#![feature(let_chains)]

use std::{
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use tokio::{fs, time::Instant};

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
}

const fn default_interval() -> usize {
    const { 360 }
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all_fields = "lowercase")]
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

impl Service {
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

    async fn get_public_v4(&self) -> Option<Ipv4Addr> {
        match self.config.ip_family {
            IpFamily::Both | IpFamily::V4 => {
                let result: Result<String> = try {
                    let response = self.ip_client.get("http://4.ipw.cn").send().await?;
                    let text = response.text().await?;
                    log::debug!(target: "get_public_v4", "{text}");
                    text
                };
                match result {
                    Ok(text) => match text.parse::<Ipv4Addr>() {
                        Ok(addr) => Some(addr),
                        Err(_parse) => {
                            log::warn!(target: "get_public_v4","it seem that ip address API is brokn? it response {text}");
                            None
                        }
                    },
                    Err(http) => {
                        log::error!(
                            "faild to get ipv4 address, it possible that the API address api is brokn: {http}"
                        );
                        None
                    }
                }
            }
            IpFamily::V6 => None,
        }
    }

    async fn get_public_v6(&self) -> Option<Ipv6Addr> {
        match self.config.ip_family {
            IpFamily::Both | IpFamily::V6 => {
                let result: Result<String> = try {
                    let response = self.ip_client.get("http://6.ipw.cn").send().await?;
                    let text = response.text().await?;
                    log::debug!(target: "get_public_v6", "{text}");
                    text
                };
                match result {
                    Ok(text) => match text.parse::<Ipv6Addr>() {
                        Ok(addr) => Some(addr),
                        Err(_parse) => {
                            log::warn!(target: "get_public_v6","it seem that ip address API is brokn? it response {text}");
                            None
                        }
                    },
                    Err(http) => {
                        log::error!(
                            "faild to get ipv4 address, it possible that the address API is brokn, or your network dont support ipv6: {http}"
                        );
                        None
                    }
                }
            }
            IpFamily::V4 => None,
        }
    }

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
        log::debug!(target: "get_zone_id", "{}", serde_json::to_string_pretty(&resp)?);

        let success = resp["success"].as_bool().unwrap();
        let result = resp["result"].as_array().unwrap();
        if let (true, Some(zone)) = (success, result.first()) {
            Ok(zone["id"].as_str().unwrap().to_owned())
        } else {
            Err(serde_json::to_string_pretty(&resp)?)?
        }
    }

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
        log::debug!(target: "get_record_id", "{}", serde_json::to_string_pretty(&resp)?);

        let success = resp["success"].as_bool().unwrap();
        let result = resp["result"].as_array().unwrap();
        if let (true, Some(zone)) = (success, result.first()) {
            Ok(zone["id"].as_str().unwrap().to_owned())
        } else {
            Err(serde_json::to_string_pretty(&resp)?)?
        }
    }

    async fn create_dns_record(&self, zone_id: &str, r#type: &str) -> Result<(String, IpAddr)> {
        let addr: IpAddr = match r#type {
            "A" => self
                .get_public_v4()
                .await
                .ok_or("faild to get ipv4 addr")?
                .into(),
            "AAAA" => self
                .get_public_v6()
                .await
                .ok_or("faild to get ipv6 addr")?
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
        log::debug!(target: "create_dns_record", "{}", serde_json::to_string_pretty(&resp)?);

        if resp["success"].as_bool().unwrap() {
            Ok((resp["result"]["id"].as_str().unwrap().to_owned(), addr))
        } else {
            Err(serde_json::to_string_pretty(&resp)?)?
        }
    }

    async fn get_or_create_record_id(&self, zone_id: &str, r#type: &str) -> Option<String> {
        match self.get_record_id(zone_id, r#type).await {
            Ok(id) => return Some(id),
            Err(e) => log::warn!("it seems no {type} record dont exist?\n{e}",),
        }

        match self.create_dns_record(zone_id, r#type).await {
            Ok((id, _)) => return Some(id),
            Err(e) => log::warn!("faild to create {type} record, it will not be updated:\n{e}"),
        }

        None
    }

    async fn get_dns_records(&self, zone_id: &str, recod_id: &str) -> Result<IpAddr> {
        let resp = self
            .cf_client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{recod_id}"
            ))
            .send()
            .await?;

        let resp = resp.json::<serde_json::Value>().await?;
        log::debug!(target: "get_dns_records", "{}", serde_json::to_string_pretty(&resp)?);

        if resp["success"].as_bool().unwrap() {
            Ok(resp["result"]["content"].as_str().unwrap().parse()?)
        } else {
            Err(serde_json::to_string_pretty(&resp)?)?
        }
    }

    async fn get_or_create_record_ip(
        &self,
        zone_id: &str,
        record_id: &str,
        r#type: &str,
    ) -> Option<IpAddr> {
        match self.get_dns_records(zone_id, record_id).await {
            Ok(addr) => return Some(addr),
            Err(e) => log::warn!("it seems no {type} record dont exist?\n{e}",),
        }

        match self.create_dns_record(zone_id, r#type).await {
            Ok((_, addr)) => return Some(addr),
            Err(e) => log::warn!("faild to create {type} record, it will not be updated:\n{e}"),
        }

        None
    }

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
        log::debug!(target: "update_dns_record", "{}", serde_json::to_string_pretty(&resp)?);

        if resp["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(serde_json::to_string_pretty(&resp)?)?
        }
    }

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
    run().await;
}

async fn run() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config_path = env::args().nth(1).unwrap_or_else(|| {
        log::warn!("config file is not specified, use `config.json` as default");
        "config.json".to_owned()
    });
    let config = fs::read_to_string(config_path)
        .await
        .expect("faild to read config file");
    let config: Config = serde_json::from_str(&config).expect("faild to deserialize config file");
    log::info!("config: {}", serde_json::to_string_pretty(&config).unwrap());

    let mut service = Service::new(config)
        .await
        .expect("faild to start up service");

    let zone = service
        .get_zone_id()
        .await
        .map_err(|e| log::error!("faild to get zone id: {e}"))
        .expect("faild to get zone id");
    log::info!("zone id got");

    let v4_record_id = match service.config.ip_family.v4() {
        true => service.get_or_create_record_id(&zone, "A").await,
        false => None,
    };

    let v6_record_id = match service.config.ip_family.v6() {
        true => service.get_or_create_record_id(&zone, "AAAA").await,
        false => None,
    };

    match (v4_record_id.is_some(), v6_record_id.is_some()) {
        (true, true) => log::info!("Servicing ipv4 and ipv6 ddns"),
        (true, false) => log::info!("Servicing ipv4 ddns"),
        (false, true) => log::info!("Servicing ipv6 ddns"),
        (false, false) => {
            log::error!("both ipv4 and ipv6 record are not exist and faild to create, abort");
            return;
        }
    }

    loop {
        if let Some(record) = v4_record_id.as_ref()
            && let Some(v4_addr) = service.get_public_v4().await
            && let Some(v4_record) = service.get_or_create_record_ip(&zone, record, "A").await
            && IpAddr::V4(v4_addr) != v4_record
        {
            log::info!("cur: {v4_addr}, record: {v4_record}. updating...");
            match service
                .update_dns_record(&zone, record, "A", v4_addr.into())
                .await
            {
                Ok(_) => log::info!("success update"),
                Err(e) => log::warn!("faild to update v4 record: {e}"),
            }
        }

        if let Some(record) = v6_record_id.as_ref()
            && let Some(v6_addr) = service.get_public_v6().await
            && let Some(v6_record) = service.get_or_create_record_ip(&zone, record, "AAAA").await
            && IpAddr::V6(v6_addr) != v6_record
        {
            log::info!("cur: {v6_addr}, record: {v6_record}. updating...");
            match service
                .update_dns_record(&zone, record, "AAAA", v6_addr.into())
                .await
            {
                Ok(_) => log::info!("success update"),
                Err(e) => log::warn!("faild to update v6 record: {e}"),
            }
        }

        service.idle().await;
    }
}
