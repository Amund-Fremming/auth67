## TODO

- [ ] Sms rate limiting/sms fraud bumping limiting. Try calling elks and ask for fraud detection
  - can try to limit exploit with combining user agent and ip address to blcok create requests, only issue is that 5g on mobiles can swap IP but might be ok here actually, because it wont block a user from creating more, just set a timeout on 30 seconds or so per number, and per user agent + ip or so?
- [ ] Rate limiting with tower govenor
- [ ] Add soft-lock with captcha/proof-of-work for sub max limit attempts
      combine them; reset the counter when the lock window expires.
- [ ] A single `crypto.secret` keys both OTP and refresh-token HMACs
      ([main.rs:31](src/main.rs#L31)); consider domain separation.
- [ ] add a ValidatedJson struct so i dont need to call validate on structs
- [ ] change email/phone fucntionality
- [ ] expand the refresh tokens to have session as parent
- [ ] fix all todos
- [ ] rate limit refresh token with device id
- [ ] social login with google and apple

### Decisions Needed

- [ ] Add runtime var for dryrun SMS in local env
- [ ] limit check on how many devices, the phone login takes in device id, can end up with many sessions if the client is stupid

### Proposals

- [ ] add test runtime to use a cache rather than sending actual messages
- [ ] add last_login_at for tracing user logins without refresh token for metrics
- [ ] create otp service, remove crypto from state, and inject into otp service
