<script lang="ts">
  import ActionMenu from '../components/ActionMenu.svelte';
  import Icon from '../components/Icon.svelte';
  import ProfileDialog, {
    type Editor,
  } from '../components/ProfileDialog.svelte';
  import type { AppSettings, StoredSubscription } from '../lib/api';
  import { api } from '../lib/api';
  import {
    isSubscriptionUrl,
    medallionText,
    type ParsedProfile,
    parseProfile,
    subscriptionTitle,
  } from '../lib/profiles';

  let {
    settings,
    selectionDisabled,
    busy,
    onSelect,
    onSaved,
    onError,
  }: {
    settings: AppSettings;
    selectionDisabled: boolean;
    busy: boolean;
    onSelect: (id: string | null) => void;
    onSaved: (message: string) => Promise<void>;
    onError: (error: unknown, title: string) => void;
  } = $props();

  const yamlTemplate = `name: Мой прокси
type: socks5
server: ""
port: 1080
  `;
  const dateTime = new Intl.DateTimeFormat('ru', {
    dateStyle: 'short',
    timeStyle: 'short',
  });

  let editor = $state.raw<Editor | null>(null);
  let reading = false;
  let tasks = $state<Record<string, 'refresh' | 'ping'>>({});
  let results = $state<Record<string, Record<string, number | null>>>({});
  const grouped = $derived.by(() => {
    const groups = new Map<string | null, ParsedProfile[]>();
    for (const stored of settings.profiles) {
      const id = stored.subscription_id ?? null;
      const profiles = groups.get(id) ?? [];
      profiles.push(parseProfile(stored));
      groups.set(id, profiles);
    }
    return groups;
  });

  export async function pasteFromClipboard() {
    if (reading || editor || busy) return;
    reading = true;
    try {
      let source = '';
      try {
        source = await api.readClipboard();
      } catch {
        // The manual paste field also works if the clipboard is unavailable.
      }
      if (isSubscriptionUrl(source)) newSubscription(source.trim());
      else editor = { type: 'import', source };
    } finally {
      reading = false;
    }
  }

  export function createProfile() {
    if (!editor && !reading && !busy)
      editor = { type: 'yaml', yaml: yamlTemplate, title: '' };
  }

  function newSubscription(url: string) {
    editor = {
      type: 'subscription',
      options: { url, title: '', send_hwid: false, auto_refresh_minutes: 0 },
    };
  }

  async function editProfile(profile: ParsedProfile) {
    if (reading || editor || busy) return;
    reading = true;
    try {
      const yaml = await api.getProfileYaml(profile.id);
      editor = { type: 'yaml', id: profile.id, yaml, title: profile.raw };
    } catch (error) {
      onError(error, 'Не удалось открыть настройки профиля');
    } finally {
      reading = false;
    }
  }

  function removeProfile(id: string, title: string) {
    editor = {
      type: 'delete',
      title,
      remove: async () => {
        await api.deleteProfile(id);
      },
    };
  }

  function editSubscription(subscription: StoredSubscription) {
    editor = {
      type: 'subscription',
      id: subscription.id,
      options: subscription,
    };
  }

  function removeSubscription(subscription: StoredSubscription) {
    editor = {
      type: 'delete',
      title: subscriptionTitle(subscription),
      remove: async () => {
        await api.deleteSubscription(subscription.id);
        delete results[subscription.id];
      },
    };
  }

  async function runGroupTask(id: string, action: 'refresh' | 'ping') {
    if (tasks[id]) return;
    tasks[id] = action;
    try {
      if (action === 'ping') {
        results[id] = await api.pingSubscription(id);
        await onSaved('Проверка TCP завершена');
      } else {
        await api.refreshSubscription(id);
        delete results[id];
        await onSaved('Подписка обновлена');
      }
    } catch (error) {
      onError(
        error,
        action === 'ping'
          ? 'Не удалось проверить TCP'
          : 'Не удалось обновить подписку',
      );
    } finally {
      delete tasks[id];
    }
  }
</script>

{#snippet profileList(profiles: ParsedProfile[], subscriptionId?: string)}
  <ul class="profile-list">
    {#each profiles as profile (profile.id)}
      {@const selected = settings.selected_profile_id === profile.id}
      {@const latency = subscriptionId
        ? results[subscriptionId]?.[profile.id]
        : undefined}
      <li class="profile-row" class:selected>
        <button
          type="button"
          class="profile-select"
          aria-pressed={selected}
          disabled={selectionDisabled}
          onclick={() => onSelect(profile.id)}
        >
          <span class="list-icon">{medallionText(profile)}</span>
          <span class="profile-name">
            <span class="list-label">{profile.label}</span>
            {#if profile.detail}
              <small>{profile.detail}</small>
            {/if}
          </span>
          {#if latency !== undefined}
            <span class="profile-latency" class:unreachable={latency === null}>
              {latency === null ? 'Нет ответа' : `${latency} мс`}
            </span>
          {/if}
          {#if selected}
            <Icon name="check" />
          {/if}
        </button>
        <button
          type="button"
          class="icon-button"
          disabled={busy}
          title="Редактировать YAML"
          aria-label={`Редактировать YAML — ${profile.label}`}
          onclick={() => editProfile(profile)}
        >
          <Icon name="chevron_right" />
        </button>
      </li>
    {/each}
  </ul>
{/snippet}

<section class="stack compact" aria-labelledby="profiles-title">
  <h2 id="profiles-title">Профили VPN</h2>
  <button
    type="button"
    class="list-button"
    class:selected={settings.selected_profile_id == null}
    aria-pressed={settings.selected_profile_id == null}
    disabled={selectionDisabled}
    onclick={() => onSelect(null)}
  >
    <span class="list-icon"><Icon name="public" /></span>
    <span class="list-label">Прямое подключение</span>
    {#if settings.selected_profile_id == null}
      <Icon name="check" />
    {/if}
  </button>

  {#each settings.subscriptions as subscription (subscription.id)}
    {@const title = subscriptionTitle(subscription)}
    {@const pending = tasks[subscription.id]}
    {@const profiles = grouped.get(subscription.id) ?? []}
    <div class="profile-group">
      <div class="profile-group-header">
        <div class="profile-group-info">
          <h3>{title}</h3>
          {#if pending}
            <small role="status"
              >{pending === 'ping' ? 'Проверка TCP…' : 'Обновление…'}</small
            >
          {:else if subscription.last_refreshed ||
            subscription.auto_refresh_minutes}
            <small>
              {#if subscription.last_refreshed}
                {dateTime.format(subscription.last_refreshed * 1000)}
              {/if}
              {#if subscription.auto_refresh_minutes}
                {subscription.last_refreshed ? ' · ' : ''}Автообновление каждые
                {subscription.auto_refresh_minutes} мин.
              {/if}
            </small>
          {/if}
        </div>
        <button
          type="button"
          class="icon-button"
          disabled={busy || !!pending}
          title="Обновить подписку"
          aria-label={`Обновить подписку — ${title}`}
          onclick={() => runGroupTask(subscription.id, 'refresh')}
        >
          <Icon name="refresh" />
        </button>
        <button
          type="button"
          class="icon-button"
          disabled={busy || !!pending || !profiles.length}
          title="TCP-пинг"
          aria-label={`TCP-пинг — ${title}`}
          onclick={() => runGroupTask(subscription.id, 'ping')}
        >
          <Icon name="speed" />
        </button>
        <ActionMenu
          icon="more_horiz"
          label={`Действия подписки — ${title}`}
          disabled={busy || !!pending}
        >
          {#snippet children(close)}
            <button
              type="button"
              onclick={() => {
                close();
                editSubscription(subscription);
              }}
            >
              <Icon name="settings" /> Настройки подписки
            </button>
            <button
              type="button"
              class="danger-action"
              onclick={() => {
                close();
                removeSubscription(subscription);
              }}
            >
              <Icon name="delete" /> Удалить подписку
            </button>
          {/snippet}
        </ActionMenu>
      </div>
      {#if profiles.length}
        {@render profileList(profiles, subscription.id)}
      {:else}
        <p class="profile-group-empty muted">
          Обновите подписку, чтобы загрузить профили.
        </p>
      {/if}
    </div>
  {/each}

  {#if grouped.has(null)}
    <div class="profile-group">
      <div class="profile-group-header"><h3>Локальные профили</h3></div>
      {@render profileList(grouped.get(null) ?? [])}
    </div>
  {:else if !settings.subscriptions.length}
    <p class="muted">Добавьте подписку или профиль через «+».</p>
  {/if}
</section>

{#if editor}
  {#key editor}
    <ProfileDialog
      {editor}
      onClose={() => (editor = null)}
      onSave={onSaved}
      onSubscriptionUrl={newSubscription}
      onDeleteProfile={removeProfile}
    />
  {/key}
{/if}
