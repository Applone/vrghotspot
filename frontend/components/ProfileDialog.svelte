<script module lang="ts">
  import type { SubscriptionOptions } from '../lib/api';

  export type Editor =
    | { type: 'yaml'; id?: string; yaml: string; title: string }
    | { type: 'subscription'; id?: string; options: SubscriptionOptions }
    | { type: 'import'; source: string }
    | { type: 'delete'; title: string; remove: () => Promise<void> };
</script>

<script lang="ts">
  import { onMount } from 'svelte';
  import { api, describeError } from '../lib/api';
  import { isSubscriptionUrl } from '../lib/profiles';

  let {
    editor,
    onClose,
    onSave,
    onSubscriptionUrl,
    onDeleteProfile,
  }: {
    editor: Editor;
    onClose: () => void;
    onSave: (message: string) => Promise<void>;
    onSubscriptionUrl: (url: string) => void;
    onDeleteProfile: (id: string, title: string) => void;
  } = $props();

  let dialog: HTMLDialogElement;
  let source = $state('');
  let url = $state('');
  let title = $state('');
  let minutes = $state<number | undefined>(0);
  let hwid = $state(false);
  let busy = $state(false);
  let failure = $state('');

  onMount(() => {
    if (editor.type === 'subscription') {
      ({
        title,
        url,
        auto_refresh_minutes: minutes,
        send_hwid: hwid,
      } = editor.options);
    } else if (editor.type === 'yaml') {
      source = editor.yaml;
    } else if (editor.type === 'import') {
      source = editor.source;
    }
    dialog.showModal();
  });

  function close() {
    dialog.close();
    onClose();
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    failure = '';
    try {
      switch (editor.type) {
        case 'yaml':
          await api.saveProfileYaml(editor.id ?? null, source);
          await onSave(editor.id ? 'Профиль сохранён' : 'Профиль добавлен');
          break;
        case 'subscription': {
          const options = {
            title,
            url,
            auto_refresh_minutes: minutes ?? 0,
            send_hwid: hwid,
          };
          if (editor.id) await api.updateSubscription(editor.id, options);
          else await api.addSubscription(options);
          await onSave(editor.id ? 'Подписка сохранена' : 'Подписка добавлена');
          break;
        }
        case 'import':
          if (isSubscriptionUrl(source)) {
            onSubscriptionUrl(source.trim());
            return;
          }
          await api.importProfiles(source);
          await onSave('Профили импортированы');
          break;
        case 'delete':
          await editor.remove();
          await onSave('Удалено');
          break;
      }
      close();
    } catch (error) {
      const detail = describeError(error);
      failure = detail.technical
        ? `${detail.title}. ${detail.technical}`
        : detail.title;
    } finally {
      busy = false;
    }
  }
</script>

<dialog
  bind:this={dialog}
  aria-labelledby="profile-dialog-title"
  oncancel={(event) => {
    event.preventDefault();
    if (!busy) close();
  }}
>
  <form class="stack" onsubmit={submit}>
    <h2 id="profile-dialog-title">
      {#if editor.type === 'yaml'}
        {editor.id ? editor.title : 'Новый профиль'}
      {:else if editor.type === 'subscription'}
        {editor.id ? 'Настройки подписки' : 'Новая подписка'}
      {:else if editor.type === 'import'}
        Вставка из буфера обмена
      {:else}
        Удалить «{editor.title}»?
      {/if}
    </h2>
    {#if editor.type === 'yaml' || editor.type === 'import'}
      <label class="field">
        <span>
          {editor.type === 'yaml'
            ? 'Конфигурация Mihomo (YAML)'
            : 'Адрес подписки или конфигурация YAML'}
        </span>
        <textarea
          class="config-editor"
          bind:value={source}
          rows={editor.type === 'yaml' ? 12 : 7}
          disabled={busy}
          autocapitalize="off"
          spellcheck="false"
          required
        ></textarea>
      </label>
      {#if editor.type === 'yaml' && !editor.id}
        <p class="muted">
          Укажите параметры прокси. Пример можно заменить своим YAML.
        </p>
      {/if}
    {:else if editor.type === 'subscription'}
      <label class="field">
        <span>Название</span>
        <input
          bind:value={title}
          disabled={busy}
          placeholder="Название провайдера"
        >
      </label>
      <label class="field">
        <span>Адрес подписки</span>
        <input
          type="url"
          bind:value={url}
          disabled={busy}
          spellcheck="false"
          required
        >
      </label>
      <label class="field">
        <span>Автообновление, мин. (0 — выключено)</span>
        <input
          type="number"
          min="0"
          max="4294967295"
          step="1"
          bind:value={minutes}
          disabled={busy}
          required
        >
      </label>
      <label class="consent">
        <input type="checkbox" bind:checked={hwid} disabled={busy}>
        Отправлять HWID провайдеру
      </label>
    {/if}

    {#if failure}
      <p class="field-error" role="alert">{failure}</p>
    {/if}

    <div class="actions dialog-actions">
      {#if editor.type === 'yaml' && editor.id}
        {@const id = editor.id}
        {@const name = editor.title}
        <button
          type="button"
          class="button text danger-action"
          disabled={busy}
          onclick={() => onDeleteProfile(id, name)}
        >
          Удалить
        </button>
      {/if}
      <button type="button" class="button text" disabled={busy} onclick={close}>
        Отмена
      </button>
      <button
        type="submit"
        class="button filled"
        disabled={busy || (editor.type === 'import' && !source.trim())}
      >
        {busy
          ? 'Подождите…'
          : editor.type === 'delete'
            ? 'Удалить'
            : editor.type === 'import'
              ? 'Импортировать'
              : 'Сохранить'}
      </button>
    </div>
  </form>
</dialog>
