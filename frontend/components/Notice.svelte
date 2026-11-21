<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let {
    title,
    problem = false,
    children,
  }: { title: string; problem?: boolean; children?: Snippet } = $props();
</script>

<section class="notice" class:problem role={problem ? 'alert' : 'status'}>
  <Icon name={problem ? 'error' : 'info'} />
  <div class="stack compact">
    <h2>{title}</h2>
    {@render children?.()}
  </div>
</section>
