import { expect, test } from 'bun:test';
import { credentialProblem } from './credentials';

test('accepts a 32-byte Wi-Fi name and rejects a longer UTF-8 name', () => {
  expect(credentialProblem('я'.repeat(16), 'password')).toBeNull();
  expect(credentialProblem('я'.repeat(17), 'password')).toMatch(/32 байт/);
});

test('rejects an empty Wi-Fi name and an embedded control character', () => {
  expect(credentialProblem('   ', 'password')).toMatch(/имя сети/);
  expect(credentialProblem('Wi-Fi\n2', 'password')).toMatch(
    /управляющие символы/,
  );
});

test('enforces the WPA2 password length and character set', () => {
  expect(credentialProblem('Wi-Fi', 'short')).toMatch(/от 8 до 63/);
  expect(credentialProblem('Wi-Fi', 'x'.repeat(64))).toMatch(/от 8 до 63/);
  expect(credentialProblem('Wi-Fi', 'пароль123')).toMatch(/латинские буквы/);
  expect(credentialProblem('Wi-Fi', ' abc!123')).toBeNull();
});
