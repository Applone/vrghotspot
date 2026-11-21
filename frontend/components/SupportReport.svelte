<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api, describeError } from '../lib/api';
  import type { ReportPreview } from '../lib/api';
  import { copyText } from '../lib/clipboard';

  let {
    kind,
    onClose,
  }: { kind: { error: string } | 'windows-ics'; onClose: () => void } =
    $props();

  let dialog: HTMLDialogElement;
  let preview = $state<ReportPreview | null>(null);
  let busy = $state(false);
  let consent = $state(false);
  let expanded = $state(false);
  let receipt = $state('');
  let failure = $state('');
  let copyStatus = $state('');
  const ics = $derived(kind === 'windows-ics');
  let active = true;

  onMount(() => {
    dialog.showModal();
    void prepare();
  });
  onDestroy(() => {
    active = false;
    if (preview)
      void api.discardSupportReport(preview.report_id).catch(() => undefined);
  });

  async function prepare() {
    if (busy) return;
    busy = true;
    failure = '';
    try {
      const report =
        kind === 'windows-ics'
          ? await api.prepareIcsReport()
          : await api.prepareSupportReport(kind.error);
      if (active) preview = report;
      else
        void api.discardSupportReport(report.report_id).catch(() => undefined);
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
      const result = await api.sendSupportReport(preview.report_id, consent);
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
      {receipt
        ? 'Отчёт отправлен'
        : ics
          ? 'Отчёт о совместимости Windows'
          : 'Отчёт об ошибке'}
    </h2>

    {#if receipt}
      <label class="field">
        <span>Номер отчёта</span>
        <input value={receipt} readonly />
      </label>
      <p role="status" class="muted">{copyStatus}</p>
      <div class="actions dialog-actions">
        <button class="button text" onclick={copyReceipt}
          >Скопировать номер</button
        >
        <button class="button tonal" onclick={() => dialog.close()}
          >Закрыть</button
        >
      </div>
    {:else}
      <p>
        {#if ics}
          В поддержку будет отправлена копия системной библиотеки
          hnetcfgclient.dll, номер сборки Windows и результат проверки сигнатур.
        {:else}
          Отчёт включает описание ошибки, сведения о приложении и очищенные
          записи журнала.
        {/if}
      </p>

      {#if preview}
        <p class="muted">Отправка на {preview.destination}</p>
        {#if !ics && preview.logs_truncated}<p class="muted">
            В отчёт вошли последние записи журнала.
          </p>{/if}
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
          <input type="checkbox" bind:checked={consent} disabled={busy} />
          {ics
            ? 'Разрешаю разовую отправку отчёта и файла hnetcfgclient.dll'
            : 'Согласен на разовую отправку отчёта'}
        </label>
      {:else}
        <p class="muted">Просмотрите отчёт перед отправкой.</p>
      {/if}

      {#if failure}<p class="field-error" role="alert">{failure}</p>{/if}
      <div class="actions dialog-actions">
        <button
          class="button text"
          disabled={busy}
          onclick={() => dialog.close()}>Отмена</button
        >
        {#if preview}
          <button
            class="button filled"
            disabled={!consent || busy}
            onclick={send}>{busy ? 'Отправка…' : 'Отправить'}</button
          >
        {:else}
          <button class="button filled" disabled={busy} onclick={prepare}
            >{busy ? 'Подготовка…' : 'Подготовить отчёт'}</button
          >
        {/if}
      </div>
    {/if}
  </div>
</dialog>
