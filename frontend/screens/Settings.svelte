<script lang="ts">
  import { untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import type { AppSettings, AppSnapshot, ConflictReport } from '../lib/api';
  import {
    credentialProblem,
    PASSWORD_MAX,
    SSID_LIMIT,
  } from '../lib/credentials';

  let {
    snapshot,
    busy,
    telemetryBusy,
    conflicts,
    onTelemetry,
    onSave,
    onClearLogs,
    onScan,
    onUpdateGeoData,
  }: {
    snapshot: AppSnapshot;
    busy: boolean;
    telemetryBusy: boolean;
    conflicts: ConflictReport | null;
    onTelemetry: (enabled: boolean) => void;
    onSave: (next: AppSettings) => void;
    onClearLogs: () => void;
    onScan: () => void;
    onUpdateGeoData: () => void;
  } = $props();

  const settings = $derived(snapshot.settings);
  const savedSsid = $derived(settings.hotspot_ssid);
  const savedPassword = $derived(settings.hotspot_passphrase);
  const savedAdapter = $derived(settings.hotspot_wifi_interface ?? '');
  const savedSharing = $derived(settings.enable_sharing);
  const savedSubscription = $derived(settings.subscription_url);

  let ssid = $state(untrack(() => savedSsid));
  let password = $state(untrack(() => savedPassword));
  let adapter = $state(untrack(() => savedAdapter));
  let sharing = $state(untrack(() => savedSharing));
  let subscription = $state(untrack(() => savedSubscription));

  $effect(() => {
    ssid = savedSsid;
  });
  $effect(() => {
    password = savedPassword;
  });
  $effect(() => {
    adapter = savedAdapter;
  });
  $effect(() => {
    sharing = savedSharing;
  });
  $effect(() => {
    subscription = savedSubscription;
  });

  const locked = $derived(snapshot.status !== 'Stopped');
  const validation = $derived(
    sharing ? credentialProblem(ssid, password) : null,
  );
  const changed = $derived(
    ssid !== savedSsid ||
      password !== savedPassword ||
      adapter !== savedAdapter ||
      sharing !== savedSharing ||
      subscription !== savedSubscription,
  );
  const adapters = $derived(snapshot.hotspot_adapters ?? snapshot.adapters);
  const radios = $derived(adapters.filter(({ kind }) => kind === 'WiFi'));
  const virtual = $derived(adapters.filter(({ kind }) => kind !== 'WiFi'));
  const missingAdapter = $derived(
    adapter && !adapters.some(({ id }) => id === adapter),
  );
  const info = $derived(settings.subscription_info);
  const logs = $derived(snapshot.logs.slice(-60).reverse());
  const trafficUnits = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ'];
  const number = new Intl.NumberFormat('ru', { maximumFractionDigits: 1 });
  const date = new Intl.DateTimeFormat('ru');
  const time = new Intl.DateTimeFormat('ru', { timeStyle: 'medium' });

  function traffic(bytes: number) {
    const unit =
      bytes > 0
        ? Math.min(
            Math.floor(Math.log(bytes) / Math.log(1024)),
            trafficUnits.length - 1,
          )
        : 0;
    return `${number.format(bytes / 1024 ** unit)} ${trafficUnits[unit]}`;
  }

  function save(event: SubmitEvent) {
    event.preventDefault();
    if (!changed || locked || busy || validation) return;
    onSave({
      ...settings,
      hotspot_ssid: ssid.trim(),
      hotspot_passphrase: password,
      hotspot_wifi_interface: adapter || null,
      enable_sharing: sharing,
      subscription_url: subscription.trim(),
    });
  }
</script>

<h1>Настройки</h1>

<form class="stack" onsubmit={save}>
  <section class="stack compact" aria-labelledby="sharing-settings">
    <h2 id="sharing-settings">Точка доступа</h2>
    {#if locked}
      <p class="muted">
        Изменение параметров сети доступно после остановки подключения.
      </p>
    {/if}
    <div class="panel stack">
      <label class="switch-row">
        <span>
          <strong>Раздача Wi-Fi</strong>
          <small>Выключите для подключения только на компьютере.</small>
        </span>
        <input
          role="switch"
          type="checkbox"
          aria-checked={sharing}
          bind:checked={sharing}
          disabled={locked || busy}
        >
      </label>
      {#if sharing}
        <label class="field">
          <span>Имя сети</span>
          <input
            bind:value={ssid}
            disabled={locked || busy}
            maxlength={SSID_LIMIT}
          >
        </label>
        <label class="field">
          <span>Пароль Wi-Fi</span>
          <input
            bind:value={password}
            disabled={locked || busy}
            maxlength={PASSWORD_MAX}
            autocomplete="off"
            spellcheck="false"
          >
        </label>
        <label class="field">
          <span>Адаптер точки доступа</span>
          <select bind:value={adapter} disabled={locked || busy}>
            <option value="">Автоматически</option>
            {#if missingAdapter}
              <option value={adapter}>Сохранённый адаптер недоступен</option>
            {/if}
            {#each radios as radio (radio.id)}
              <option value={radio.id}>
                {radio.description && radio.description !== radio.name
                  ? `${radio.description} · ${radio.name}`
                  : radio.name}
              </option>
            {/each}
            {#if virtual.length}
              <optgroup label="Интерфейсы Wi-Fi Direct">
                {#each virtual as item (item.id)}
                  <option value={item.id}>
                    {item.name}{item.ipv4_addresses?.length
                      ? ` · ${item.ipv4_addresses.join(', ')}`
                      : ''}
                    · {item.is_up ? 'активен' : 'неактивен'}
                  </option>
                {/each}
              </optgroup>
            {/if}
          </select>
        </label>
      {/if}
      {#if validation && !locked}
        <p class="field-error">{validation}</p>
      {/if}
    </div>
  </section>

  <section class="stack compact" aria-labelledby="privacy-settings">
    <h2 id="privacy-settings">Конфиденциальность</h2>
    <div class="panel stack compact">
      <label class="switch-row">
        <span>
          <strong>Автоматическая телеметрия</strong>
          <small>
            Статистика запусков, подключений и категорий ошибок. Включена по
            умолчанию.
          </small>
        </span>
        <input
          role="switch"
          type="checkbox"
          aria-checked={settings.telemetry_enabled}
          checked={settings.telemetry_enabled}
          disabled={telemetryBusy ||
            busy ||
            (!snapshot.telemetry.configured && !settings.telemetry_enabled)}
          onchange={(event) => onTelemetry(event.currentTarget.checked)}
        >
      </label>
      <p class="muted" role="status">
        {#if telemetryBusy}
          Сохранение настройки…
        {:else if !snapshot.telemetry.configured}
          Сервер телеметрии не настроен.
        {:else if !settings.telemetry_enabled}
          Автоматическая отправка отключена.
        {:else if !snapshot.telemetry.active ||
          snapshot.telemetry.consecutive_failures > 0}
          Доставка телеметрии пока не подтверждена.
        {/if}
      </p>
    </div>
  </section>

  {#if info.title ||
    info.announce ||
    info.support_url ||
    info.download_bytes != null ||
    info.total_bytes != null ||
    info.expires_at != null}
    <section class="stack compact">
      <h2>Подписка VPN</h2>
      <div class="panel stack compact">
        {#if info.title}
          <strong>{info.title}</strong>
        {/if}
        {#if info.announce}
          <p class="announcement">{info.announce}</p>
        {/if}
        <dl class="facts">
          {#if info.download_bytes != null}
            <div>
              <dt>Получено</dt>
              <dd>{traffic(info.download_bytes)}</dd>
            </div>
          {/if}
          {#if info.total_bytes != null}
            <div>
              <dt>Лимит</dt>
              <dd>{traffic(info.total_bytes)}</dd>
            </div>
          {/if}
          {#if info.expires_at != null}
            <div>
              <dt>Действует до</dt>
              <dd>{date.format(info.expires_at * 1000)}</dd>
            </div>
          {/if}
          {#if info.support_url}
            <div>
              <dt>Поддержка</dt>
              <dd>{info.support_url}</dd>
            </div>
          {/if}
        </dl>
      </div>
    </section>
  {/if}

  <details class="panel settings-disclosure">
    <summary>Дополнительные настройки</summary>
    <div class="stack">
      <label class="field">
        <span>Адрес подписки</span>
        <input
          bind:value={subscription}
          disabled={locked || busy}
          spellcheck="false"
        >
      </label>
      <div class="actions">
        <button
          class="button tonal"
          type="button"
          disabled={busy}
          onclick={onUpdateGeoData}
        >
          <Icon name="public" /> Обновить геоданные
        </button>
        <button
          class="button text"
          type="button"
          disabled={busy}
          onclick={onScan}
        >
          Проверить конфликты
        </button>
      </div>
      {#if conflicts}
        <dl class="facts">
          <div>
            <dt>Интерфейсы TUN</dt>
            <dd>{conflicts.tun_interfaces.length}</dd>
          </div>
          <div>
            <dt>Системный прокси</dt>
            <dd>{conflicts.system_proxy ? 'Включён' : 'Выключен'}</dd>
          </div>
          <div>
            <dt>Конфликтующие процессы</dt>
            <dd>{conflicts.conflicting_processes.length}</dd>
          </div>
        </dl>
      {/if}
      <section class="stack compact">
        <div class="section-heading">
          <h2>Журнал</h2>
          <button
            class="button text"
            type="button"
            disabled={busy || !logs.length}
            onclick={onClearLogs}
          >
            Очистить
          </button>
        </div>
        {#if logs.length}
          <ul class="logs">
            {#each logs as entry}
              <li>
                <span>
                  {time.format(entry.timestamp * 1000)} · {entry.level}
                </span>
                {entry.message}
              </li>
            {/each}
          </ul>
        {:else}
          <p class="muted">Журнал пуст.</p>
        {/if}
      </section>
    </div>
  </details>

  <div class="actions">
    <button
      type="submit"
      class="button filled"
      disabled={busy || locked || !changed || !!validation}
    >
      Сохранить изменения
    </button>
  </div>
</form>
