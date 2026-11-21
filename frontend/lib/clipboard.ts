export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Embedded WebKit can deny the Clipboard API.
  }

  const area = document.createElement('textarea');
  area.className = 'clipboard-fallback';
  area.value = text;
  document.body.append(area);
  area.select();
  try {
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    area.remove();
  }
}
