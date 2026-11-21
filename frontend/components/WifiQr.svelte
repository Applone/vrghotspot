<script lang="ts">
  import { encodeText, wifiPayload } from '../lib/qr';

  let { ssid, passphrase }: { ssid: string; passphrase: string } = $props();

  const quietZone = 4;
  const symbol = $derived.by(() => {
    try {
      const matrix = encodeText(wifiPayload(ssid, passphrase)).modules;
      const paths = matrix.flatMap((row, y) =>
        row.map((dark, x) =>
          dark ? `M${x + quietZone} ${y + quietZone}h1v1h-1z` : '',
        ),
      );
      return { path: paths.join(''), size: matrix.length + quietZone * 2 };
    } catch {
      return null;
    }
  });
</script>

{#if symbol}
  <svg
    class="wifi-qr"
    role="img"
    aria-label={`QR-код сети ${ssid}`}
    viewBox={`0 0 ${symbol.size} ${symbol.size}`}
    shape-rendering="crispEdges"
    width="144"
    height="144"
  >
    <rect width={symbol.size} height={symbol.size} fill="white" />
    <path d={symbol.path} fill="black" />
  </svg>
{/if}
