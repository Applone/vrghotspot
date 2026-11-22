<script lang="ts">
  import { type Snippet, untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Notice from '../components/Notice.svelte';
  import WifiQr from '../components/WifiQr.svelte';
  import type { AppSnapshot } from '../lib/api';
  import {
    credentialProblem,
    PASSWORD_MAX,
    SSID_LIMIT,
  } from '../lib/credentials';

  let {
    snapshot,
    busy,
    starting,
    stopping,
    onStart,
    onStop,
    profilesContent,
    onCopy,
  }: {
    snapshot: AppSnapshot;
    busy: boolean;
    starting: boolean;
    stopping: boolean;
    onStart: (ssid: string, password: string) => void;
    onStop: () => void;
    profilesContent: Snippet;
    onCopy: (value: string) => void;
  } = $props();

  const savedSsid = $derived(snapshot.settings.hotspot_ssid);
  const savedPassword = $derived(snapshot.settings.hotspot_passphrase);
  let ssid = $state(untrack(() => savedSsid));
  let password = $state(untrack(() => savedPassword));
  $effect(() => {
    ssid = savedSsid;
  });
  $effect(() => {
    password = savedPassword;
  });

  const running = $derived(snapshot.status === 'Running');
  const editable = $derived(
    snapshot.status === 'Stopped' && !busy && !stopping,
  );
  const sharing = $derived(snapshot.settings.enable_sharing);
  const selected = $derived(
    snapshot.settings.profiles.find(
      (profile) => profile.id === snapshot.settings.selected_profile_id,
    ),
  );

  const missingUplink = $derived(!snapshot.uplink.any_uplink);
  const missingWifi = $derived(sharing && !snapshot.has_physical_wifi_adapter);
  const problem = $derived(
    missingUplink
      ? 'У компьютера нет подключения к интернету.'
      : sharing && !missingWifi
        ? credentialProblem(ssid, password)
        : null,
  );
  const accessPoint = $derived(sharing || snapshot.sharing_active);
  const statusLabel = $derived(
    stopping || snapshot.status === 'Stopping'
      ? 'Остановка…'
      : starting || snapshot.status === 'Starting'
        ? 'Запуск…'
        : snapshot.sharing_active
          ? 'Активна'
          : running
            ? selected
              ? 'VPN на компьютере подключён'
              : 'Прямое подключение активно'
            : accessPoint
              ? 'Выключена'
              : 'Выключено',
  );

  const plural = new Intl.PluralRules('ru');
  const deviceForms: Partial<Record<Intl.LDMLPluralRule, string>> = {
    one: 'устройство',
    few: 'устройства',
  };
</script>

<section
  class="hero"
  class:active={snapshot.sharing_active}
  class:connecting={starting || snapshot.status === 'Starting'}
  aria-label={accessPoint ? 'Точка доступа Wi-Fi' : 'Состояние подключения'}
>
  {#if accessPoint}
    <h1>Точка доступа Wi-Fi</h1>
  {/if}
  <div class="connection-controls">
    <div class="connection-state">
      <p class="hero-status" aria-live="polite">{statusLabel}</p>
      {#if snapshot.sharing_active && snapshot.connected_clients != null}
        <p class="device-count">
          <Icon name="devices" />
          {snapshot.connected_clients}
          {deviceForms[plural.select(snapshot.connected_clients)] ??
            'устройств'}
        </p>
      {/if}
    </div>
    {#if running || starting || snapshot.status !== 'Stopped' || stopping}
      <button
        type="button"
        class="button tonal"
        disabled={stopping || snapshot.status === 'Stopping'}
        onclick={onStop}
      >
        <Icon name="stop" /> Остановить
      </button>
    {:else}
      <button
        type="button"
        class="button filled"
        disabled={!editable || missingWifi || !!problem}
        onclick={() => onStart(ssid.trim(), password)}
      >
        <Icon name="play_arrow" /> Запустить
      </button>
    {/if}
  </div>
</section>

{#if editable && problem}
  <Notice title="Запуск недоступен" problem>
    <p>{problem}</p>
    {#if missingUplink}
      <details class="disclosure">
        <summary>Подключение по USB</summary>
        <p>
          Подключите телефон кабелем и включите USB-модем в его сетевых
          настройках.
        </p>
      </details>
    {/if}
  </Notice>
{/if}

{@render profilesContent()}

{#if sharing || snapshot.sharing_active}
  <section class="stack compact" aria-labelledby="wifi-title">
    <h2 id="wifi-title">Сеть Wi-Fi</h2>
    <div class="credential-card">
      <div class="credential">
        <label>
          <span class="field-label">Имя сети</span>
          <input bind:value={ssid} readonly={!editable} maxlength={SSID_LIMIT}>
        </label>
        <button
          type="button"
          class="icon-button"
          title="Скопировать имя сети"
          aria-label="Скопировать имя сети"
          onclick={() => onCopy(ssid)}
        >
          <Icon name="content_copy" />
        </button>
      </div>
      <div class="credential">
        <label>
          <span class="field-label">Пароль Wi-Fi</span>
          <input
            bind:value={password}
            readonly={!editable}
            maxlength={PASSWORD_MAX}
            autocomplete="off"
            spellcheck="false"
          >
        </label>
        <button
          type="button"
          class="icon-button"
          title="Скопировать пароль"
          aria-label="Скопировать пароль"
          onclick={() => onCopy(password)}
        >
          <Icon name="content_copy" />
        </button>
      </div>
      {#if snapshot.sharing_active}
        <details class="qr-disclosure">
          <summary>QR-код для подключения</summary>
          <WifiQr
            ssid={snapshot.settings.hotspot_ssid}
            passphrase={snapshot.settings.hotspot_passphrase}
          />
        </details>
      {/if}
    </div>
  </section>
{/if}
