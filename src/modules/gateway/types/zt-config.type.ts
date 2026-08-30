export type ZtConfig = {
  hmacSecret: string;
  signMode: 'hmac' | 'ed25519';
  signingKid: string;
  signingPrivateKey: string;
};
