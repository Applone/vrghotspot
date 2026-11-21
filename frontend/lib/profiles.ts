/**
 * Subscription nodes are shown exactly as the provider named them: nothing is
 * grouped by country and no "connection methods" are invented. All that happens
 * here is splitting off a leading flag emoji — it goes on the medallion so it is
 * not duplicated in the label.
 */
import type { StoredVpnProfile } from './api';

export type ParsedProfile = {
  id: string;
  /** Node name exactly as it appears in the config. */
  raw: string;
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
  const raw = profile.name.trim();
  const flag = extractLeadingFlag(raw);
  return {
    id: profile.id,
    raw,
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
