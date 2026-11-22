use super::{AppError, AppSettings, HotspotController};
use crate::config::subscription::{
    DEFAULT_SUBSCRIPTION_URL, FetchedSubscription, StoredSubscription, StoredVpnProfile,
    SubscriptionClient, SubscriptionDocument, SubscriptionError, SubscriptionOptions,
    parse_proxy_yaml, parse_subscription_response, proxy_endpoint, sanitize_proxy,
    stored_profiles_from_document,
};
use crate::ui::events::{EventSink, UiEvent};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Instant, interval, timeout};
use tracing::warn;
use uuid::Uuid;

const PING_TIMEOUT: Duration = Duration::from_secs(3);
const PING_CONCURRENCY: usize = 12;
const REFRESH_POLL: Duration = Duration::from_secs(15);

pub(super) fn seeded_subscriptions() -> Vec<StoredSubscription> {
    let url = std::env::var("VRG_SUBSCRIPTION_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SUBSCRIPTION_URL.to_owned());
    if url.trim().is_empty() {
        return Vec::new();
    }
    vec![StoredSubscription::new(SubscriptionOptions {
        url,
        ..Default::default()
    })]
}

impl AppSettings {
    pub(super) fn migrate_subscriptions(&mut self) {
        let current_url = std::mem::take(&mut self.subscription_url);
        let current_info = std::mem::take(&mut self.subscription_info);
        let mut sources = HashMap::new();

        for url in std::iter::once(current_url.as_str())
            .chain(
                self.profiles
                    .iter()
                    .filter_map(|profile| profile.source_url.as_deref()),
            )
            .filter(|url| !url.trim().is_empty())
        {
            sources.entry(url.to_owned()).or_insert_with(|| {
                let mut subscription = StoredSubscription::new(SubscriptionOptions {
                    url: url.to_owned(),
                    ..Default::default()
                });
                if url == current_url {
                    subscription.info = current_info.clone();
                }
                let id = subscription.id;
                self.subscriptions.push(subscription);
                id
            });
        }

        for profile in &mut self.profiles {
            if let Some(url) = profile.source_url.take() {
                profile.subscription_id = sources.get(url.as_str()).copied();
            }
        }
    }

    fn subscription(&self, id: Uuid) -> Result<&StoredSubscription, AppError> {
        self.subscriptions
            .iter()
            .find(|group| group.id == id)
            .ok_or(AppError::SubscriptionNotFound)
    }

    fn ensure_unique_url(&self, url: &str, editing: Option<Uuid>) -> Result<(), AppError> {
        if self
            .subscriptions
            .iter()
            .any(|group| Some(group.id) != editing && group.options.url == url)
        {
            return Err(AppError::DuplicateSubscription);
        }
        Ok(())
    }

    fn repair_selection(&mut self) {
        if self.selected_profile_id.is_some() && self.selected_profile().is_none() {
            self.selected_profile_id = self.profiles.first().map(|profile| profile.id.clone());
        }
    }

    fn apply_subscription(
        &mut self,
        id: Uuid,
        fetched: FetchedSubscription,
    ) -> Result<(), AppError> {
        let mut incoming = usable_profiles(fetched.document)?;
        let first_import = self.profiles.is_empty();
        let mut previous = HashMap::<String, Vec<StoredVpnProfile>>::new();
        self.profiles.retain(|profile| {
            if profile.subscription_id != Some(id) {
                return true;
            }
            previous
                .entry(StoredVpnProfile::identifier(&profile.proxy))
                .or_default()
                .push(profile.clone());
            false
        });

        // Reserve the exact matches before considering renamed nodes. Providers
        // can publish multiple profiles that share the same connection fields.
        for profile in &mut incoming {
            if let Some(matches) = previous.get_mut(&StoredVpnProfile::identifier(&profile.proxy))
                && let Some(index) = matches
                    .iter()
                    .position(|old| old.name == profile.name && old.proxy == profile.proxy)
            {
                let old = matches.remove(index);
                profile.id = old.id;
                profile.proxy_override = old.proxy_override;
                profile.subscription_id = Some(id);
            }
        }
        for profile in &mut incoming {
            if profile.subscription_id.is_some() {
                continue;
            }
            if let Some(matches) = previous.get_mut(&StoredVpnProfile::identifier(&profile.proxy))
                && let Some(index) = matches
                    .iter()
                    .position(|old| old.name == profile.name)
                    .or_else(|| (matches.len() == 1).then_some(0))
            {
                let old = matches.remove(index);
                profile.id = old.id;
                profile.proxy_override = old.proxy_override;
            } else {
                profile.id = Uuid::new_v4().to_string();
            }
            profile.subscription_id = Some(id);
        }

        if first_import {
            self.selected_profile_id = incoming.first().map(|profile| profile.id.clone());
        }
        self.profiles.extend(incoming);
        self.repair_selection();

        let group = self
            .subscriptions
            .iter_mut()
            .find(|group| group.id == id)
            .ok_or(AppError::SubscriptionNotFound)?;
        group.info = fetched.info;
        group.last_refreshed = Some(unix_now());
        Ok(())
    }
}

impl<S: Clone + Send + Sync + 'static + EventSink> HotspotController<S> {
    pub(super) async fn change_profiles<T>(
        &self,
        change: impl FnOnce(&mut AppSettings) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let mut stored = self.settings.write().await;
        let mut next = stored.clone();
        let result = change(&mut next)?;
        next.save_to_disk()?;
        *stored = next;
        drop(stored);
        self.ui.emit(UiEvent::ProfilesChanged);
        Ok(result)
    }

    pub async fn import_profiles(&self, source: &str) -> Result<(), AppError> {
        let imported = usable_profiles(parse_subscription_response(source)?)?;
        self.add_manual_profiles(imported).await
    }

    async fn add_manual_profiles(
        &self,
        mut imported: Vec<StoredVpnProfile>,
    ) -> Result<(), AppError> {
        self.change_profiles(|settings| {
            for profile in &mut imported {
                profile.id = Uuid::new_v4().to_string();
            }
            if settings.profiles.is_empty() {
                settings.selected_profile_id = imported.first().map(|profile| profile.id.clone());
            }
            settings.profiles.extend(imported);
            Ok(())
        })
        .await
    }

    pub async fn save_profile_yaml(&self, id: Option<String>, yaml: &str) -> Result<(), AppError> {
        let proxy = parse_proxy_yaml(yaml)?;
        let Some(id) = id else {
            return self
                .add_manual_profiles(vec![StoredVpnProfile::from_proxy(proxy)])
                .await;
        };
        self.change_profiles(|settings| {
            let profile = settings
                .profiles
                .iter_mut()
                .find(|profile| profile.id == id)
                .ok_or_else(|| AppError::ProfileNotFound(id.clone()))?;
            if profile.subscription_id.is_some() {
                profile.proxy_override = (proxy != sanitize_proxy(&profile.proxy)).then_some(proxy);
            } else {
                *profile = StoredVpnProfile {
                    id,
                    ..StoredVpnProfile::from_proxy(proxy)
                };
            }
            Ok(())
        })
        .await
    }

    pub async fn profile_yaml(&self, id: &str) -> Result<String, AppError> {
        let settings = self.settings.read().await;
        let profile = settings
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| AppError::ProfileNotFound(id.to_owned()))?;
        let mut proxy = sanitize_proxy(profile.effective_proxy());
        if let Some(map) = proxy.as_object_mut() {
            map.entry("name")
                .or_insert_with(|| profile.display_name().into());
        }
        serde_yaml::to_string(&proxy).map_err(|error| SubscriptionError::from(error).into())
    }

    pub async fn select_profile(&self, id: Option<String>) -> Result<(), AppError> {
        let _lifecycle = self.lifecycle.lock().await;
        if self.status().await != super::HotspotStatus::Stopped {
            return Err(AppError::SettingsLockedWhileRunning);
        }
        self.change_profiles(|settings| {
            if let Some(id) = &id
                && !settings.profiles.iter().any(|profile| profile.id == *id)
            {
                return Err(AppError::ProfileNotFound(id.clone()));
            }
            settings.selected_profile_id = id;
            Ok(())
        })
        .await
    }

    pub async fn delete_profile(&self, id: &str) -> Result<(), AppError> {
        self.change_profiles(|settings| {
            let original_len = settings.profiles.len();
            settings.profiles.retain(|profile| profile.id != id);
            if settings.profiles.len() == original_len {
                return Err(AppError::ProfileNotFound(id.to_owned()));
            }
            settings.repair_selection();
            Ok(())
        })
        .await
    }

    pub async fn add_subscription(&self, options: SubscriptionOptions) -> Result<(), AppError> {
        let options = options.normalize()?;
        self.settings
            .read()
            .await
            .ensure_unique_url(&options.url, None)?;
        let client = self.subscription_client(options.send_hwid).await?;
        let fetched = client.fetch(&options.url).await?;
        self.change_profiles(|settings| {
            settings.ensure_unique_url(&options.url, None)?;
            let group = StoredSubscription::new(options);
            let id = group.id;
            settings.subscriptions.push(group);
            settings.apply_subscription(id, fetched)
        })
        .await
    }

    pub async fn update_subscription(
        &self,
        id: Uuid,
        options: SubscriptionOptions,
    ) -> Result<(), AppError> {
        let options = options.normalize()?;
        let previous = self.settings.read().await.subscription(id)?.options.clone();
        let fetched = if previous.url != options.url {
            self.settings
                .read()
                .await
                .ensure_unique_url(&options.url, Some(id))?;
            Some(
                self.subscription_client(options.send_hwid)
                    .await?
                    .fetch(&options.url)
                    .await?,
            )
        } else {
            None
        };
        self.change_profiles(|settings| {
            settings.ensure_unique_url(&options.url, Some(id))?;
            let group = settings
                .subscriptions
                .iter_mut()
                .find(|group| group.id == id)
                .ok_or(AppError::SubscriptionNotFound)?;
            if group.options != previous {
                return Err(AppError::SubscriptionChanged);
            }
            group.options = options;
            if let Some(fetched) = fetched {
                settings.apply_subscription(id, fetched)?;
            }
            Ok(())
        })
        .await
    }

    pub async fn delete_subscription(&self, id: Uuid) -> Result<(), AppError> {
        self.change_profiles(|settings| {
            settings.subscription(id)?;
            settings.subscriptions.retain(|group| group.id != id);
            settings
                .profiles
                .retain(|profile| profile.subscription_id != Some(id));
            settings.repair_selection();
            Ok(())
        })
        .await
    }

    async fn subscription_client(&self, send_hwid: bool) -> Result<SubscriptionClient, AppError> {
        let settings = self.settings.read().await;
        let user_agent = settings.user_agent_override.clone();
        let mut hwid = settings.installation_id;
        drop(settings);
        if send_hwid && hwid.is_none() {
            hwid = Some(
                self.change_profiles(|settings| {
                    Ok(*settings.installation_id.get_or_insert_with(Uuid::new_v4))
                })
                .await?,
            );
        }
        Ok(SubscriptionClient::new(
            user_agent,
            hwid.filter(|_| send_hwid),
        )?)
    }

    pub async fn refresh_subscription(&self, id: Uuid) -> Result<(), AppError> {
        self.refresh_subscription_inner(id, None).await
    }

    async fn refresh_subscription_inner(
        &self,
        id: Uuid,
        automatic: Option<u64>,
    ) -> Result<(), AppError> {
        let _refresh = self.subscription_refresh.lock().await;
        let group = self.settings.read().await.subscription(id)?.clone();
        if let Some(now) = automatic
            && !group.refresh_due(now, None)
        {
            return Ok(());
        }
        let options = group.options;
        let client = self.subscription_client(options.send_hwid).await?;
        let fetched = client.fetch(&options.url).await?;
        self.change_profiles(|settings| {
            let current = &settings.subscription(id)?.options;
            if current.url != options.url || current.send_hwid != options.send_hwid {
                return Err(AppError::SubscriptionChanged);
            }
            settings.apply_subscription(id, fetched)
        })
        .await
    }

    pub async fn run_subscription_updates(&self) {
        let mut ticker = interval(REFRESH_POLL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut attempts = HashMap::new();
        loop {
            ticker.tick().await;
            let subscriptions = self.settings.read().await.subscriptions.clone();
            attempts.retain(|id, _| subscriptions.iter().any(|group| group.id == *id));
            for group in subscriptions {
                let now = unix_now();
                let id = group.id;
                if group.refresh_due(now, attempts.get(&id).copied()) {
                    attempts.insert(id, now);
                    if let Err(error) = self.refresh_subscription_inner(id, Some(now)).await {
                        warn!(%id, %error, "automatic subscription refresh failed");
                    }
                }
            }
        }
    }

    pub async fn ping_subscription(
        &self,
        id: Uuid,
    ) -> Result<HashMap<String, Option<u64>>, AppError> {
        let settings = self.settings.read().await;
        settings.subscription(id)?;
        let mut targets: VecDeque<_> = settings
            .profiles
            .iter()
            .filter(|profile| profile.subscription_id == Some(id))
            .map(|profile| {
                let endpoint = proxy_endpoint(profile.effective_proxy())
                    .map(|(host, port)| (host.to_owned(), port));
                (profile.id.clone(), endpoint)
            })
            .collect();
        drop(settings);

        let mut pending = JoinSet::new();
        let mut results = HashMap::new();
        loop {
            while pending.len() < PING_CONCURRENCY {
                let Some((id, endpoint)) = targets.pop_front() else {
                    break;
                };
                pending.spawn(async move {
                    let latency = match endpoint {
                        Some((host, port)) => tcp_ping(&host, port).await,
                        None => None,
                    };
                    (id, latency)
                });
            }
            match pending.join_next().await {
                Some(Ok((id, latency))) => {
                    results.insert(id, latency);
                }
                Some(Err(error)) => warn!(%error, "TCP ping task failed"),
                None => return Ok(results),
            }
        }
    }
}

fn usable_profiles(document: SubscriptionDocument) -> Result<Vec<StoredVpnProfile>, AppError> {
    let profiles = stored_profiles_from_document(document);
    if profiles.is_empty() {
        return Err(SubscriptionError::NoUsableNode.into());
    }
    Ok(profiles)
}

async fn tcp_ping(host: &str, port: u16) -> Option<u64> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let start = Instant::now();
    timeout(PING_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .ok()?
        .ok()?;
    Some(start.elapsed().as_millis() as u64)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn provider(url: &str) -> StoredSubscription {
        StoredSubscription::new(SubscriptionOptions {
            url: url.to_owned(),
            ..Default::default()
        })
    }

    fn fetched(proxies: Vec<Value>, title: &str) -> FetchedSubscription {
        FetchedSubscription {
            document: SubscriptionDocument::Proxies(proxies),
            info: super::super::SubscriptionInfo {
                title: Some(title.to_owned()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn migrates_all_legacy_sources_without_changing_the_selection() {
        let proxy = json!({"type": "socks5", "server": "example.test", "port": 1080});
        let mut settings: AppSettings = serde_json::from_value(json!({
            "profiles": [
                {"id": "old-0", "name": "A", "proxy": proxy, "source_url": "https://a.test/sub"},
                {"id": "old-1", "name": "B", "proxy": proxy, "source_url": "https://b.test/sub"},
                {"id": "old-2", "name": "Local", "proxy": proxy}
            ],
            "selected_profile_id": "old-1",
            "subscription_url": "https://b.test/sub",
            "subscription_info": {"title": "Provider B"},
            "geo_data": {},
            "onboarding_complete": true
        }))
        .unwrap();

        settings.migrate_subscriptions();
        assert_eq!(settings.subscriptions.len(), 2);
        let a = settings.profiles[0].subscription_id.unwrap();
        let b = settings.profiles[1].subscription_id.unwrap();
        assert_ne!(a, b);
        assert_eq!(
            settings.subscription(a).unwrap().options.url,
            "https://a.test/sub"
        );
        assert_eq!(
            settings.subscription(b).unwrap().info.title.as_deref(),
            Some("Provider B")
        );
        assert_eq!(settings.selected_profile().unwrap().id, "old-1");
        assert!(settings.profiles[2].subscription_id.is_none());

        let mut loaded: AppSettings =
            serde_json::from_value(serde_json::to_value(&settings).unwrap()).unwrap();
        loaded.migrate_subscriptions();
        assert_eq!(settings, loaded);
    }

    #[test]
    fn refresh_preserves_local_overrides_and_other_subscriptions() {
        let a = provider("https://a.test/sub");
        let b = provider("https://b.test/sub");
        let (a_id, b_id) = (a.id, b.id);
        let mut settings = AppSettings {
            subscriptions: vec![a, b],
            ..Default::default()
        };
        let node = json!({"name": "One", "type": "vless", "server": "example.test", "port": 443});
        let mut variant = node.clone();
        variant["name"] = json!("Two");
        variant["flow"] = json!("xtls-rprx-vision");
        settings
            .apply_subscription(
                a_id,
                fetched(vec![node.clone(), variant.clone()], "Provider A"),
            )
            .unwrap();
        settings
            .apply_subscription(b_id, fetched(vec![node.clone()], "Provider B"))
            .unwrap();
        let selected = settings.selected_profile_id.clone();
        let other = settings.profiles[2].clone();
        assert_ne!(settings.profiles[0].id, other.id);
        let local =
            json!({"name": "Custom", "type": "socks5", "server": "localhost", "port": 1080});
        settings.profiles[0].proxy_override = Some(local.clone());

        let mut renamed = node.clone();
        renamed["name"] = json!("Provider renamed");
        settings
            .apply_subscription(a_id, fetched(vec![variant, renamed], "New title"))
            .unwrap();

        assert_eq!(settings.selected_profile_id, selected);
        assert_eq!(
            settings.selected_profile().unwrap().effective_proxy(),
            &local
        );
        assert_eq!(settings.profiles[0], other);
        assert_eq!(
            settings.subscription(b_id).unwrap().info.title.as_deref(),
            Some("Provider B")
        );

        let cached = settings.clone();
        assert!(
            settings
                .apply_subscription(a_id, fetched(vec![], "Empty response"))
                .is_err()
        );
        assert_eq!(settings, cached);

        settings
            .apply_subscription(
                a_id,
                fetched(
                    vec![json!({
                        "name": "New server", "type": "socks5", "server": "new.test", "port": 1080
                    })],
                    "Replaced",
                ),
            )
            .unwrap();
        assert!(
            settings
                .profiles
                .iter()
                .all(|profile| Some(&profile.id) != selected.as_ref())
        );
        assert!(settings.selected_profile().is_some());
    }

    #[test]
    fn auto_refresh_respects_interval_and_failed_attempts() {
        let mut subscription = provider("https://example.test");
        assert!(!subscription.refresh_due(200, None));
        subscription.options.auto_refresh_minutes = 2;
        subscription.last_refreshed = Some(200);
        assert!(!subscription.refresh_due(319, None));
        assert!(subscription.refresh_due(320, None));
        assert!(!subscription.refresh_due(400, Some(320)));
        assert!(subscription.refresh_due(440, Some(320)));
    }

    #[tokio::test]
    async fn tcp_ping_connects_to_the_profile_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ping, accepted) = tokio::join!(
            tcp_ping("127.0.0.1", port),
            timeout(PING_TIMEOUT, listener.accept()),
        );
        assert!(ping.is_some());
        assert!(accepted.unwrap().is_ok());
        assert!(tcp_ping("127.0.0.1", 0).await.is_none());
    }
}
