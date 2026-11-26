// Prints a random secret that meets connect-mongo's encryption rules
// (at least 2 uppercase, 2 lowercase, 2 numbers, 2 symbols). Run: npm run secret
const crypto = require('crypto');

const pick = (chars, n) => Array.from({ length: n }, () => chars[crypto.randomInt(chars.length)]);
const chars = [
  ...pick('ABCDEFGHJKLMNPQRSTUVWXYZ', 10),
  ...pick('abcdefghijkmnpqrstuvwxyz', 10),
  ...pick('23456789', 8),
  ...pick('!@#%^*-_=+.', 8),
];
for (let i = chars.length - 1; i > 0; i--) {
  const j = crypto.randomInt(i + 1);
  [chars[i], chars[j]] = [chars[j], chars[i]];
}
console.log(chars.join(''));
