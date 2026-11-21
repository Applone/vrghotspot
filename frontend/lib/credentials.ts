export const SSID_LIMIT = 32;
export const PASSWORD_MAX = 63;

const encoder = new TextEncoder();

export function credentialProblem(
  ssid: string,
  password: string,
): string | null {
  const name = ssid.trim();
  if (!name) return 'Укажите имя сети Wi-Fi.';
  if (encoder.encode(name).length > SSID_LIMIT)
    return 'Сократите имя сети до 32 байт.';
  if (/\p{Cc}/u.test(name)) return 'Удалите управляющие символы из имени сети.';
  if (!/^[\x20-\x7e]*$/.test(password)) {
    return 'Используйте в пароле латинские буквы, цифры, пробелы или знаки препинания.';
  }
  if (password.length < 8 || password.length > PASSWORD_MAX) {
    return 'Длина пароля Wi-Fi должна составлять от 8 до 63 символов.';
  }
  return null;
}
