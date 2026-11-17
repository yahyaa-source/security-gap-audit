# Security Gap Checklist

## Accounts and wallets
- [ ] Unique, strong password per account; password manager in use
- [ ] 2FA enabled (authenticator app preferred over SMS)
- [ ] Wallet/bank PIN not shared and not reused
- [ ] Alerts for transactions turned on
- [ ] Recovery phone/email current
- [ ] Dormancy/expiry notices verified via the official app, never via links in SMS
- [ ] SIM PIN set; SIM-swap protection requested from carrier

## Devices
- [ ] OS and apps updated
- [ ] Screen lock enabled; disk encryption on
- [ ] Apps installed only from official stores
- [ ] Unused app permissions revoked

## Code and repos
- [ ] No secrets in source or git history
- [ ] `.gitignore` covers `.env`, keys, build output
- [ ] Dependencies pinned and scanned
- [ ] Branch protection and required reviews
- [ ] Least-privilege tokens with expiry
- [ ] Input validation, parameterized queries
- [ ] Logging excludes sensitive data

## Phishing awareness
- [ ] Sender verified through an independent channel
- [ ] Never share OTP/PIN with anyone, including "support"
