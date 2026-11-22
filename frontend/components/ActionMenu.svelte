<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let {
    icon,
    label,
    disabled = false,
    children,
  }: {
    icon: string;
    label: string;
    disabled?: boolean;
    children: Snippet<[() => void]>;
  } = $props();

  let menu: HTMLDivElement;
  let trigger: HTMLButtonElement;
  let open = $state(false);

  function close() {
    open = false;
    trigger.focus();
  }

  function outside(event: MouseEvent) {
    if (open && !event.composedPath().includes(menu)) {
      open = false;
    }
  }

  function keydown(event: KeyboardEvent) {
    if (open && event.key === 'Escape') {
      event.preventDefault();
      close();
    }
  }
</script>

<svelte:window onclick={outside} onkeydown={keydown} />

<div class="action-menu" bind:this={menu}>
  <button
    type="button"
    bind:this={trigger}
    class="icon-button"
    aria-label={label}
    aria-expanded={open}
    {disabled}
    title={label}
    onclick={() => (open = !open)}
  >
    <Icon name={icon} />
  </button>
  {#if open}
    <div class="action-menu-items">{@render children(close)}</div>
  {/if}
</div>
