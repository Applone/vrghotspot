/** Typed bindings for the Rust side. Field names mirror the serde output. */
import { invoke } from '@tauri-apps/api/core';

export type HotspotStatus = 'Stopped' | 'Starting' | 'Running' | 'Stopping';

export type GeoDataSettings = {
  asset_dir?: string | null;
  geoip_url?: string | null;
  geosite_url?: string | null;
};

export type SubscriptionInfo = {
  title?: string | null;
  announce?: string | null;
  support_url?: string | null;
  web_page_url?: string | null;
  upload_bytes?: number | null;
  download_bytes?: number | null;
  total_bytes?: number | null;
  expires_at?: number | null;
};

export type StoredVpnProfile = {
  id: string;
  name: string;
  proxy: unknown;
  source_url?: string | null;
};

export type AppSettings = {
  user_agent_override?: string | null;
  profiles: StoredVpnProfile[];
  selected_profile_id?: string | null;
  hotspot_wifi_interface?: string | null;
  enable_sharing: boolean;
  hotspot_ssid: string;
  hotspot_passphrase: string;
  subscription_url: string;
  subscription_info: SubscriptionInfo;
  onboarding_complete: boolean;
  telemetry_enabled: boolean;
  geo_data: GeoDataSettings;
};

export type NetworkAdapter = {
  id: string;
  name: string;
  kind: string;
  description?: string;
  ipv4_addresses?: string[];
  is_up: boolean;
  has_ip_address: boolean;
  has_default_route: boolean;
  supports_hotspot: boolean;
};

export type UplinkStatus = {
  wired_present: boolean;
  wired_interface?: string | null;
  wired_has_internet: boolean;
  any_uplink: boolean;
};

export type LogEntry = {
  timestamp: number;
  level: string;
  target: string;
  message: string;
};

export type ConflictReport = {
  tun_interfaces: string[];
  system_proxy?: { server: string; bypass?: string | null } | null;
  conflicting_processes: string[];
};

export type TelemetryStatus = {
  configured: boolean;
  active: boolean;
  last_delivery_unix?: number | null;
  consecutive_failures: number;
  next_attempt_in_seconds?: number | null;
};

export type ReportPreview = {
  report_id: string;
  destination: string;
  payload: string;
  log_count: number;
  logs_truncated: boolean;
};

export type ReportReceipt = {
  report_id: string;
};

export type AppSnapshot = {
  settings: AppSettings;
  status: HotspotStatus;
  adapters: NetworkAdapter[];
  hotspot_adapters?: NetworkAdapter[];
  has_physical_wifi_adapter: boolean;
  wifi_adapter_error?: string | null;
  uplink: UplinkStatus;
  connected_clients?: number | null;
  sharing_active: boolean;
  ics_signature_mismatch: boolean;
  logs: LogEntry[];
  telemetry: TelemetryStatus;
  reports_configured: boolean;
};

export type RuntimeEvent =
  | { type: 'StatusChanged'; payload: HotspotStatus }
  | { type: 'ConnectionStarted'; payload: { pid?: number | null } }
  | { type: 'ConnectionStopped' }
  | { type: 'SettingsChanged' }
  | { type: 'ProfilesChanged' }
  | { type: 'ConflictWarning'; payload: ConflictReport }
  | { type: 'SharingEnabled'; payload: { wifi_interface: string } }
  | { type: 'SharingFailed'; payload: string }
  | { type: 'Warning'; payload: string }
  | { type: 'Error'; payload: string };

export const RUNTIME_EVENT = 'vrg://runtime-event';

export const api = {
  snapshot: () => invoke<AppSnapshot>('get_snapshot'),
  saveSettings: (settings: AppSettings) =>
    invoke<AppSettings>('save_settings', { settings }),
  setTelemetryEnabled: (enabled: boolean) =>
    invoke<AppSettings>('set_telemetry_enabled', { enabled }),
  prepareSupportReport: (error: string) =>
    invoke<ReportPreview>('prepare_support_report', { error }),
  prepareIcsReport: () => invoke<ReportPreview>('prepare_ics_report'),
  sendSupportReport: (reportId: string, consent: boolean) =>
    invoke<ReportReceipt>('send_support_report', { reportId, consent }),
  discardSupportReport: (reportId: string) =>
    invoke<void>('discard_support_report', { reportId }),
  importSubscription: (source: string) =>
    invoke<AppSettings>('import_subscription', { source }),
  refreshSubscription: () => invoke<AppSettings>('refresh_subscription'),
  completeOnboarding: () => invoke<AppSettings>('complete_onboarding'),
  selectProfile: (profileId: string) =>
    invoke<AppSettings>('select_profile', { profileId }),
  deleteProfile: (profileId: string) =>
    invoke<AppSettings>('delete_profile', { profileId }),
  start: () => invoke<HotspotStatus>('start_hotspot'),
  stop: () => invoke<HotspotStatus>('stop_hotspot'),
  updateGeoData: () => invoke<void>('update_geo_data'),
  scanConflicts: () => invoke<ConflictReport>('scan_conflicts'),
  clearLogs: () => invoke<void>('clear_logs'),
};

export type ErrorMessage = {
  title: string;
  detail?: string;
  technical?: string;
};

const knownErrors: { match: RegExp; title: string; detail?: string }[] = [
  {
    match: /settings cannot be changed while/i,
    title: 'Настройки заблокированы',
    detail: 'Остановите подключение перед изменением параметров сети.',
  },
  {
    match:
      /multiple active hotspot adapters|selected Windows hotspot adapter did not become active/i,
    title: 'Не удалось выбрать адаптер Wi-Fi',
    detail: 'Укажите адаптер точки доступа в настройках.',
  },
  {
    match: /turn off Windows Mobile Hotspot/i,
    title: 'Мобильный хот-спот Windows уже включён',
    detail: 'Отключите его в параметрах Windows и повторите запуск.',
  },
  {
    match: /start VRG Hotspot as Administrator/i,
    title: 'Требуются права администратора',
    detail: 'Откройте VRG Hotspot от имени администратора.',
  },
  {
    match: /CAP_NET_ADMIN|setcap|tunnel device/i,
    title: 'Не удалось создать туннель',
    detail: 'Проверьте права приложения и доступность сетевого драйвера.',
  },
  {
    match:
      /single-radio|uplink interface|cannot host an access point|dropped its upstream|dropped the station/i,
    title:
      'Адаптер Wi-Fi не может одновременно подключаться к сети и раздавать её',
    detail:
      'Подключите компьютер по Ethernet, через USB-модем или с помощью другого адаптера Wi-Fi.',
  },
  {
    match: /no physical Wi-?Fi adapter/i,
    title: 'Адаптер Wi-Fi не обнаружен',
    detail: 'Подключите адаптер или отключите раздачу Wi-Fi в настройках.',
  },
  {
    match: /startup timed out|activation on .* timed out/i,
    title: 'Истекло время запуска',
  },
  {
    match:
      /tunnel health probe failed|could not verify internet access through the VPN tunnel/i,
    title: 'Нет доступа к интернету через VPN',
    detail: 'Проверьте исходное подключение или выберите другой профиль VPN.',
  },
  {
    match: /did not contain a usable proxy/i,
    title: 'В подписке нет поддерживаемых профилей',
  },
  { match: /invalid proxy link/i, title: 'Недопустимая ссылка на профиль VPN' },
  {
    match: /no subscription is configured/i,
    title: 'Адрес подписки не задан',
    detail:
      'Укажите адрес в дополнительных настройках или добавьте профиль по ссылке.',
  },
  {
    match: /not authorized|privileged network configuration failed|pkexec/i,
    title: 'Не удалось получить права на настройку сети',
  },
  { match: /NetworkManager|D-Bus/i, title: 'Ошибка сетевой службы' },
  {
    match: /telemetry configuration failed/i,
    title: 'Не удалось изменить настройку телеметрии',
  },
];

export function describeError(
  error: unknown,
  fallback = 'Не удалось выполнить операцию',
): ErrorMessage {
  const raw = error instanceof Error ? error.message : String(error ?? '');
  const technical = raw.trim().replace(/\s+/g, ' ');
  const known = knownErrors.find(({ match }) => match.test(technical));
  return {
    title: known?.title ?? fallback,
    detail: known?.detail,
    technical:
      technical.length > 600 ? `${technical.slice(0, 599)}…` : technical,
  };
}
