<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import type { AppSettings } from '../lib/api';
  import { medallionText, parseProfile } from '../lib/profiles';

  let {
    settings,
    busy,
    onSelect,
    onImport,
    onRefresh,
    onDelete,
  }: {
    settings: AppSettings;
    busy: boolean;
    onSelect: (id: string) => void;
    onImport: (source: string) => Promise<boolean>;
    onRefresh: () => void;
    onDelete: (id: string) => void;
  } = $props();

  let adding = $state(false);
  let source = $state('');
  const profiles = $derived(settings.profiles.map(parseProfile));

  async function importProfile(event: SubmitEvent) {
    event.preventDefault();
    if (await onImport(source.trim())) {
      source = '';
      adding = false;
    }
  }
</script>

<h1>Профили VPN</h1>
{#if profiles.length}
  <ul class="profile-list">
    {#each profiles as profile (profile.id)}
      {@const selected = settings.selected_profile_id === profile.id}
      <li>
        <button
          class="list-button"
          class:selected
          aria-pressed={selected}
          disabled={busy}
          onclick={() => onSelect(profile.id)}
        >
          <span class="list-icon">{medallionText(profile)}</span>
          <span class="list-label">{profile.label}</span>
          {#if selected}<Icon name="check" />{/if}
        </button>
      </li>
    {/each}
  </ul>
{:else}
  <p class="muted">
    Профилей VPN нет. Импортируйте профиль или обновите подписку.
  </p>
{/if}

{#if adding}
  <form class="panel stack compact" onsubmit={importProfile}>
    <label class="field">
      <span>Ссылка на профиль или подписку</span>
      <textarea rows="3" bind:value={source} spellcheck="false" required
      ></textarea>
    </label>
    <div class="actions">
      <button class="button filled" disabled={busy || !source.trim()}
        >Импортировать</button
      >
      <button
        class="button text"
        type="button"
        disabled={busy}
        onclick={() => (adding = false)}>Отмена</button
      >
    </div>
  </form>
{:else}
  <div class="actions">
    <button class="button tonal" disabled={busy} onclick={() => (adding = true)}
      ><Icon name="add" /> Импортировать</button
    >
    <button class="button text" disabled={busy} onclick={onRefresh}
      ><Icon name="refresh" /> Обновить подписку</button
    >
  </div>
{/if}

{#if settings.selected_profile_id && profiles.length > 1}
  <button
    class="button text"
    disabled={busy}
    onclick={() => onDelete(settings.selected_profile_id ?? '')}
  >
    <Icon name="delete" /> Удалить выбранный профиль
  </button>
{/if}
