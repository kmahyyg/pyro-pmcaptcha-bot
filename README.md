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