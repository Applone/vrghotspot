<script lang="ts">
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import ActionMenu from './components/ActionMenu.svelte';
  import Icon from './components/Icon.svelte';
  import IcsReport from './components/IcsReport.svelte';
  import Notice from './components/Notice.svelte';
  import type {
    AppSnapshot,
    ConflictReport,
    ErrorMessage,
    HotspotStatus,
    RuntimeEvent,
  } from './lib/api';
  import { api, describeError, RUNTIME_EVENT } from './lib/api';
  import { copyText } from './lib/clipboard';
  import Home from './screens/Home.svelte';
  import Profiles from './screens/Profiles.svelte';
  import Settings from './screens/Settings.svelte';

  type Route = 'home' | 'settings';
  type Message = ErrorMessage & {
    problem?: boolean;
    sharing?: boolean;
  };

  const RETRY_LIMIT = 3;
  const RETRY_DELAY = 10;
  const POLL_INTERVAL = 2200;
  const PASSWORD_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';

  let snapshot = $state.raw<AppSnapshot | null>(null);
  let route = $state<Route>('home');
  let profiles = $state<{
    pasteFromClipboard: () => Promise<void>;
    createProfile: () => void;
  }>();
  let message = $state<Message | null>(null);
  let showIcsReport = $state(false);
  let conflicts = $state<ConflictReport | null>(null);
  let busy = $state(false);
  let starting = $state(false);
  let stopping = $state(false);
  let retry = $state<{ attempt: number; seconds: number } | null>(null);

  let pollFailures = 0;
  let refreshVersion = 0;
  let refreshPending = false;
  let cancelStart = false;
  let feedback = $state('');
  let feedbackTimer: number | undefined;

  function showFeedback(text: string) {
    feedback = text;
    window.clearTimeout(feedbackTimer);
    feedbackTimer = window.setTimeout(() => (feedback = ''), 2500);
  }

  function showError(error: unknown, fallback?: string, sharing = false) {
    message = {
      ...describeError(error, fallback),
      problem: true,
      sharing,
    };
  }

  function trackStatus(
    previous: HotspotStatus | undefined,
    status: HotspotStatus,
  ) {
    if (status === 'Running') {
      retry = null;
    } else if (previous === 'Running' && status === 'Stopped' && !stopping) {
      retry ??= { attempt: 0, seconds: RETRY_DELAY };
    }
  }

  async function refresh() {
    const version = ++refreshVersion;
    refreshPending = true;
    try {
      const next = await api.snapshot();
      if (version !== refreshVersion) return;
      trackStatus(snapshot?.status, next.status);
      snapshot = next;
      if (next.ics_signature_mismatch && message?.sharing) message = null;
      if (
        pollFailures > 0 &&
        message?.title === 'Нет связи со службой приложения'
      )
        message = null;
      pollFailures = 0;
    } catch (error) {
      if (version !== refreshVersion) return;
      pollFailures += 1;
      if (!snapshot || pollFailures === 3)
        showError(error, 'Нет связи со службой приложения');
    } finally {
      if (version === refreshVersion) refreshPending = false;
    }
  }

  function handleEvent(event: RuntimeEvent) {
    switch (event.type) {
      case 'ConflictWarning':
        conflicts = event.payload;
        break;
      case 'SharingFailed':
        showError(event.payload, 'Не удалось запустить точку доступа', true);
        break;
      case 'Warning':
        showError(event.payload, 'Предупреждение');
        break;
      case 'Error':
        showError(event.payload);
        break;
      default:
        void refresh();
    }
  }

  onMount(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    void listen<RuntimeEvent>(RUNTIME_EVENT, ({ payload }) => {
      if (active) handleEvent(payload);
    })
      .then((stop) => {
        if (active) unlisten = stop;
        else stop();
      })
      .catch(() => {
        // Polling continues when the platform event channel is unavailable.
      });
    void refresh();
    const timer = window.setInterval(() => {
      if (!refreshPending) void refresh();
    }, POLL_INTERVAL);
    return () => {
      active = false;
      refreshVersion += 1;
      unlisten?.();
      window.clearInterval(timer);
      window.clearTimeout(feedbackTimer);
    };
  });

  async function runTask(
    task: () => Promise<unknown>,
    fallback?: string,
    success?: string,
  ): Promise<boolean> {
    if (busy || stopping) return false;
    busy = true;
    message = null;
    try {
      await task();
      if (success) showFeedback(success);
      return true;
    } catch (error) {
      showError(error, fallback);
      return false;
    } finally {
      await refresh();
      busy = false;
    }
  }

  async function setup() {
    await runTask(async () => {
      const settings = snapshot?.settings;
      if (!settings) return;
      if (settings.hotspot_passphrase.length < 8) {
        const bytes = crypto.getRandomValues(new Uint8Array(10));
        const password = Array.from(
          bytes,
          (value) => PASSWORD_ALPHABET[value % PASSWORD_ALPHABET.length],
        ).join('');
        await api.saveSettings({ ...settings, hotspot_passphrase: password });
      }
      await api.completeOnboarding();
      for (const subscription of settings.subscriptions) {
        if (
          subscription.last_refreshed ||
          settings.profiles.some(
            (profile) => profile.subscription_id === subscription.id,
          )
        )
          continue;
        try {
          await api.refreshSubscription(subscription.id);
        } catch (error) {
          showError(error, 'Не удалось обновить подписку');
        }
      }
    }, 'Не удалось завершить настройку');
  }

  async function start(ssid?: string, password?: string) {
    const settings = snapshot?.settings;
    if (!settings || busy || stopping) return;
    cancelStart = false;
    starting = true;
    try {
      await runTask(async () => {
        if (
          settings.enable_sharing &&
          ssid != null &&
          password != null &&
          (ssid !== settings.hotspot_ssid ||
            password !== settings.hotspot_passphrase)
        ) {
          await api.saveSettings({
            ...settings,
            hotspot_ssid: ssid,
            hotspot_passphrase: password,
          });
        }
        if (!cancelStart) await api.start();
      }, 'Не удалось запустить подключение');
    } finally {
      starting = false;
    }
  }

  async function stop() {
    if (stopping) return;
    cancelStart = true;
    stopping = true;
    retry = null;
    message = null;
    try {
      await api.stop();
    } catch (error) {
      showError(error, 'Не удалось остановить подключение');
    } finally {
      await refresh();
      stopping = false;
    }
  }

  async function copy(value: string) {
    const copied = await copyText(value);
    showFeedback(copied ? 'Скопировано' : 'Не удалось скопировать');
  }

  $effect(() => {
    if (
      !retry ||
      retry.attempt >= RETRY_LIMIT ||
      busy ||
      stopping ||
      snapshot?.status !== 'Stopped' ||
      showIcsReport
    )
      return;
    const timer = window.setTimeout(() => {
      if (!retry) return;
      if (retry.seconds > 1) {
        retry.seconds -= 1;
      } else {
        retry = { attempt: retry.attempt + 1, seconds: RETRY_DELAY };
        void start();
      }
    }, 1000);
    return () => window.clearTimeout(timer);
  });

  function navigate(next: Route) {
    route = next;
    window.scrollTo(0, 0);
  }
</script>

<header class="app-bar">
  <div class="app-bar-inner">
    {#if route !== 'home'}
      <button
        type="button"
        class="icon-button"
        aria-label="Назад"
        title="Назад"
        onclick={() => navigate('home')}
      >
        <Icon name="arrow_back" />
      </button>
    {:else if snapshot}
      <button
        type="button"
        class="icon-button"
        title="Настройки"
        aria-label="Настройки"
        onclick={() => navigate('settings')}
      >
        <Icon name="settings" />
      </button>
    {/if}
    {#if snapshot?.settings.onboarding_complete && route === 'home'}
      <ActionMenu
        icon="add"
        label="Добавить профиль или подписку"
        disabled={busy || stopping || !profiles}
      >
        {#snippet children(close)}
          <button
            type="button"
            onclick={() => {
              close();
              void profiles?.pasteFromClipboard();
            }}
          >
            <Icon name="content_paste" /> Вставить из буфера обмена
          </button>
          <button
            type="button"
            onclick={() => {
              close();
              profiles?.createProfile();
            }}
          >
            <Icon name="edit" /> Ручной ввод
          </button>
        {/snippet}
      </ActionMenu>
    {/if}
  </div>
</header>

<main class="screen stack">
  {#if snapshot && route === 'home' && !snapshot.has_physical_wifi_adapter}
    <Notice
      title={snapshot.wifi_adapter_error
        ? 'Не удалось проверить адаптер Wi-Fi'
        : 'Адаптер Wi-Fi не обнаружен'}
      problem={snapshot.settings.enable_sharing}
    >
      {#if snapshot.wifi_adapter_error}
        <p>{snapshot.wifi_adapter_error}</p>
      {:else}
        <p>
          {snapshot.settings.enable_sharing
            ? 'Для запуска точки доступа подключите адаптер Wi-Fi. Для работы только на компьютере отключите раздачу в настройках.'
            : 'Для раздачи Wi-Fi требуется адаптер. Подключение на компьютере доступно при наличии интернета.'}
        </p>
      {/if}
    </Notice>
  {/if}
  {#if snapshot?.ics_signature_mismatch}
    <Notice title="Сигнатуры системной библиотеки не совпадают" problem>
      <p>
        Точка доступа недоступна. Проверка сигнатур hnetcfgclient.dll для этой
        сборки Windows не пройдена.
      </p>
      {#if snapshot.reports_configured}
        <button
          type="button"
          class="button text"
          onclick={() => (showIcsReport = true)}
        >
          Просмотреть отчёт
        </button>
      {:else}
        <p>Сервер отчётов не настроен.</p>
      {/if}
    </Notice>
  {/if}

  {#if message &&
    !(message.sharing && (starting || snapshot?.ics_signature_mismatch))}
    <Notice title={message.title} problem={message.problem}>
      {#if message.detail}
        <p>{message.detail}</p>
      {/if}
      {#if message.technical && message.detail}
        <details class="disclosure">
          <summary>Технические сведения</summary>
          <p>{message.technical}</p>
        </details>
      {:else if message.technical}
        <p>{message.technical}</p>
      {/if}
      <div class="actions">
        <button
          type="button"
          class="button text"
          onclick={() => (message = null)}
        >
          Закрыть
        </button>
      </div>
    </Notice>
  {/if}

  {#if retry && route === 'home' && !starting && snapshot?.status === 'Stopped'}
    <Notice title="Подключение прервано" problem>
      {#if retry.attempt < RETRY_LIMIT}
        <p>Повторный запуск через {retry.seconds} с.</p>
      {/if}
      <div class="actions">
        <button
          type="button"
          class="button text"
          onclick={() => {
            retry = null;
            void start();
          }}
        >
          Повторить
        </button>
        <button
          type="button"
          class="button text"
          onclick={() => (retry = null)}
        >
          Отменить повтор
        </button>
      </div>
    </Notice>
  {/if}

  {#if !snapshot}
    {#if !message}
      <p role="status" class="muted">Загрузка…</p>
    {/if}
  {:else if route === 'settings'}
    <Settings
      {snapshot}
      busy={busy || stopping}
      {conflicts}
      onSave={(next) =>
        runTask(
          () => api.saveSettings(next),
          'Не удалось сохранить настройки',
          'Настройки сохранены',
        )}
      onScan={() =>
        runTask(async () => {
          conflicts = await api.scanConflicts();
        }, 'Не удалось проверить конфликты')}
      onClearLogs={() => runTask(api.clearLogs, 'Не удалось очистить журнал')}
      onUpdateGeoData={() =>
        runTask(
          api.updateGeoData,
          'Не удалось обновить геоданные',
          'Геоданные обновлены',
        )}
    />
  {:else if !snapshot.settings.onboarding_complete}
    <section class="panel stack">
      <span class="list-icon"><Icon name="wifi_tethering" /></span>
      <h1>Первый запуск</h1>
      <p class="muted">
        Начальная настройка сохранит пароль точки доступа.
        {#if snapshot.settings.subscriptions.length}
          Приложение также попробует загрузить профили из настроенных подписок.
        {/if}
      </p>
      <div class="actions">
        <button
          type="button"
          class="button filled"
          disabled={busy}
          onclick={setup}
        >
          {busy ? 'Настройка…' : 'Продолжить'}
        </button>
      </div>
    </section>
  {:else}
    {@const current = snapshot}
    <Home
      snapshot={current}
      {busy}
      {starting}
      {stopping}
      onStart={start}
      onStop={stop}
      onCopy={copy}
    >
      {#snippet profilesContent()}
        <Profiles
          bind:this={profiles}
          settings={current.settings}
          selectionDisabled={busy || stopping || current.status !== 'Stopped'}
          busy={busy || stopping}
          onSelect={(id) =>
            runTask(() => api.selectProfile(id), 'Не удалось выбрать профиль')}
          onSaved={async (text) => {
            await refresh();
            showFeedback(text);
          }}
          onError={showError}
        />
      {/snippet}
    </Home>
  {/if}
</main>

{#if showIcsReport}
  <IcsReport onClose={() => (showIcsReport = false)} />
{/if}

<div class="snackbar" class:visible={!!feedback} role="status">{feedback}</div>
