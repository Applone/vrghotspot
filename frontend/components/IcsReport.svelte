<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import type { ReportPreview } from '../lib/api';
  import { api, describeError } from '../lib/api';
  import { copyText } from '../lib/clipboard';

  let { onClose }: { onClose: () => void } = $props();

  let dialog: HTMLDialogElement;
  let preview = $state<ReportPreview | null>(null);
  let busy = $state(false);
  let consent = $state(false);
  let expanded = $state(false);
  let receipt = $state('');
  let failure = $state('');
  let copyStatus = $state('');
  let active = true;

  onMount(() => {
    dialog.showModal();
    void prepare();
  });
  onDestroy(() => {
    active = false;
    if (preview)
      void api.discardIcsReport(preview.report_id).catch(() => undefined);
  });

  async function prepare() {
    if (busy) return;
    busy = true;
    failure = '';
    try {
      const report = await api.prepareIcsReport();
      if (active) preview = report;
      else void api.discardIcsReport(report.report_id).catch(() => undefined);
    } catch (error) {
      const detail = describeError(error, 'Не удалось подготовить отчёт');
      if (detail.technical?.includes('report exceeds size limit')) {
        failure =
          'Размер отчёта с библиотекой превышает лимит сервера (2 МиБ).';
      } else if (detail.technical?.includes('DLL changed')) {
        failure =
          'Библиотека изменилась после проверки. Повторите запуск точки доступа.';
      } else {
        failure = detail.technical
          ? `${detail.title}. ${detail.technical}`
          : detail.title;
      }
    } finally {
      busy = false;
    }
  }

  async function send() {
    if (!preview || !consent || busy) return;
    busy = true;
    failure = '';
    try {
      const result = await api.sendIcsReport(preview.report_id, consent);
      receipt = result.report_id;
    } catch (error) {
      const detail = describeError(error);
      failure = /expired/i.test(detail.technical ?? '')
        ? 'Срок действия отчёта истёк. Закройте окно и подготовьте новый отчёт.'
        : 'Сервер не подтвердил отправку. Повторите попытку через несколько секунд.';
    } finally {
      busy = false;
    }
  }

  function cancel(event: Event) {
    if (busy) event.preventDefault();
  }

  async function copyReceipt() {
    copyStatus = (await copyText(receipt))
      ? 'Номер скопирован.'
      : 'Не удалось скопировать номер.';
  }
</script>

<dialog
  bind:this={dialog}
  aria-labelledby="report-title"
  onclose={onClose}
  oncancel={cancel}
>
  <div class="stack">
    <h2 id="report-title">
      {receipt ? 'Отчёт отправлен' : 'Отчёт о совместимости Windows'}
    </h2>

    {#if receipt}
      <p>
        Отправьте номер отчёта в поддержку, чтобы мы могли найти библиотеку.
      </p>
      <label class="field">
        <span>Номер отчёта</span>
        <input value={receipt} readonly>
      </label>
      <p role="status" class="muted">{copyStatus}</p>
      <div class="actions dialog-actions">
        <button type="button" class="button text" onclick={copyReceipt}>
          Скопировать номер
        </button>
        <button
          type="button"
          class="button tonal"
          onclick={() => dialog.close()}
        >
          Закрыть
        </button>
      </div>
    {:else}
      <p>
        Будет отправлена копия системной библиотеки hnetcfgclient.dll, номер
        сборки Windows и результат проверки сигнатур.
      </p>

      {#if preview}
        <p class="muted">Отправка на {preview.destination}</p>
        <details class="disclosure" bind:open={expanded}>
          <summary>Содержимое отчёта</summary>
          {#if expanded}
            <textarea
              aria-label="Содержимое отчёта"
              rows="8"
              readonly
              value={preview.payload}
            ></textarea>
          {/if}
        </details>
        <label class="consent">
          <input type="checkbox" bind:checked={consent} disabled={busy}>
          Разрешаю разовую отправку отчёта и файла hnetcfgclient.dll
        </label>
      {:else}
        <p class="muted">Просмотрите отчёт перед отправкой.</p>
      {/if}

      {#if failure}
        <p class="field-error" role="alert">{failure}</p>
      {/if}
      <div class="actions dialog-actions">
        <button
          type="button"
          class="button text"
          disabled={busy}
          onclick={() => dialog.close()}
        >
          Отмена
        </button>
        {#if preview}
          <button
            type="button"
            class="button filled"
            disabled={!consent || busy}
            onclick={send}
          >
            {busy ? 'Отправка…' : 'Отправить'}
          </button>
        {:else}
          <button
            type="button"
            class="button filled"
            disabled={busy}
            onclick={prepare}
          >
            {busy ? 'Подготовка…' : 'Подготовить отчёт'}
          </button>
        {/if}
      </div>
    {/if}
  </div>
</dialog>
