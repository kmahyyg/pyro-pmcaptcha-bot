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

## Docker-compose

Use `bind` mount to mount following file with long syntax in `volumes` key:

- `/app/pmcaptcha_myoungram.session`
- `/app/pmroSecrets.py`

Use `attach` subcommand to input authentication data of Telegram.

Use `echo "" > $(docker inspect --format='{{.LogPath}}' <CONTAINER_NAME_OR_ID>)`  to clean logs which logged all your input to prevent sensitive information leakage.

Use `^P + ^Q` to detach from container.
