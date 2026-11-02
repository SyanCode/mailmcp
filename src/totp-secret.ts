import { generateSecret, otpauthUrl } from "./totp.js";

const secret = generateSecret();
console.log(`ADMIN_TOTP_SECRET=${secret}`);
console.log(`\nAdd it as an account in Google Authenticator: "Enter a setup key", type Time based.`);
console.log(`Or open the otpauth URL in a QR generator: ${otpauthUrl(secret)}`);
