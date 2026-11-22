import type { StoredSubscription, StoredVpnProfile } from './api';

export type ParsedProfile = {
  id: string;
  /** Node name exactly as it appears in the config. */
  raw: string;
  detail: string;
  flag: string | null;
  /** Name without the leading flag — what is printed on the card. */
  label: string;
};

export function isRegionalIndicator(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return Boolean(codePoint && codePoint >= 0x1f1e6 && codePoint <= 0x1f1ff);
}

export function extractLeadingFlag(value: string): string | null {
  const characters = Array.from(value.trim());
  if (
    characters.length >= 2 &&
    isRegionalIndicator(characters[0]) &&
    isRegionalIndicator(characters[1])
  ) {
    return `${characters[0]}${characters[1]}`;
  }
  return null;
}

function stripLeadingFlag(value: string): string {
  const characters = Array.from(value.trim());
  if (
    characters.length >= 2 &&
    isRegionalIndicator(characters[0]) &&
    isRegionalIndicator(characters[1])
  ) {
    return characters.slice(2).join('').trim();
  }
  return value.trim();
}

export function parseProfile(profile: StoredVpnProfile): ParsedProfile {
  const proxy = (profile.proxy_override ?? profile.proxy) as Record<
    string,
    unknown
  > | null;
  const field = (key: string) =>
    typeof proxy?.[key] === 'string' ? proxy[key].trim() : '';
  const raw = (
    field('name') ||
    (profile.proxy_override ? field('server') : '') ||
    profile.name
  ).trim();
  const protocol = field('type').toUpperCase();
  const transport = field('network');
  const detail = [protocol, transport].filter(Boolean).join(' · ');
  const flag = extractLeadingFlag(raw);
  return {
    id: profile.id,
    raw,
    detail,
    flag,
    label: stripLeadingFlag(raw) || raw,
  };
}

/** The flag, or the first letter of the name when there is none. */
export function medallionText(profile: {
  flag: string | null;
  label: string;
}): string {
  if (profile.flag) {
    return profile.flag;
  }
  return profile.label.trim().slice(0, 1).toUpperCase() || '?';
}

export function subscriptionTitle(subscription: StoredSubscription): string {
  const title = subscription.title || subscription.info.title;
  if (title) return title;
  try {
    return new URL(subscription.url).hostname;
  } catch {
    return 'Подписка VPN';
  }
}

export function isSubscriptionUrl(source: string): boolean {
  return /^https?:\/\/\S+$/i.test(source.trim());
}
