# Pyrogram SelfBot

Currently:
- PM Captcha

## Redis Schema

```
ulist_<CHATID>: 1   // allowed user
ulist_<CHATID>: 2   // blocked user
pmstat_<CHATID>: curTs  // Wait for Verification
uinverify_<CHATID>: comma splited data // verification data; key: suuid,ts
```

ErrCode:

- 9001: Already blocked previously
- 9002: Verification Expired within 10min
- 9004: Verification Expired within 95s
- 9003: Signature Verification Failed
- 9099: Database error
- 9098: Python Execution Error