#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import base64
import hashlib
import hmac
import platform
import sys
import time
from uuid import uuid4 as uuidgen

import redis
import uvloop
from pyrogram import Client, filters, types

import pyroSecrets

uvloop.install()

app = Client(name="pmcaptcha_myoungram",
             api_id=pyroSecrets.PYRO_API_ID,
             api_hash=pyroSecrets.PYRO_API_SECRET,
             app_version=pyroSecrets.PYRO_MY_TITLE + " v1.0",
             device_model=platform.node())

VERIF_TMPL = """
请在 90s 内点击 [此处]({veriurl}) 完成验证。如到期未完成，请联系 {botuser} 解封。
Please click [here]({veriurl}) within 90s to finish verification if you are a human. If not, you will be blocked, contact {botuser} to unblock.

Current Time: {tsstr}
Powered By MYounGram v1.0
"""

VERIF_FAIL = """
人机验证失败，验证不通过，请联系 {botuser} 解封。
Human Verification Failed, Contact {botuser} to unblock. ERRCODE: {errcode}

Powered By MYounGram v1.0
"""

VERIF_PASS = """
人机验证通过，感谢您的使用。
Human Verification Pass! Congrats! 

Powered By MYounGram v1.0
"""

VERIF_500 = """
内部异常，验证结果待定，请联系 {botuser} 报障。
We've encountered internal error, please contact {botuser} to report issue. ERRCODE: {errcode}

Powered By MYounGram v1.0
"""

redis_cli = redis.Redis(host=pyroSecrets.DB_REDIS_IP, port=pyroSecrets.DB_REDIS_PORT,
                        db=pyroSecrets.DB_REDIS_DB, password=pyroSecrets.DB_REDIS_PASS,
                        username=pyroSecrets.DB_REDIS_USER)


@app.on_message(filters=filters.private)
async def captcha_pm(client: Client, message: types.Message):
    # if msg is a bot, ignore
    if message.from_user.is_bot:
        return

    # if msg is from self or contact, ignore
    from_user = message.from_user
    if from_user.is_contact and not from_user.is_self:
        return

    # others, means strangers
    msg_chat_id = message.chat.id    
    # if already whitelisted, ignore
    uStatus = redis_cli.get("ulist_" + str(msg_chat_id))
    if uStatus == b"1":
        return

    # If message is outgoing, means already known, add to k-v for bypass
    # if message is from original user and not send to saved message, it should be auto unban
    if message.outgoing and message.chat.id != message.from_user.id:
        if redis_cli.set("ulist_" + str(msg_chat_id), 1):
            print("User " + str(msg_chat_id) + " added to whitelist due to outgoing first.")
            await client.unblock_user(msg_chat_id)
            return

    # bypass self message or message from verified user like telegram official
    if message.from_user.is_self or message.from_user.is_verified or message.chat.is_support:
        return

    # If already blocked, return
    if redis_cli.get("ulist_" + str(msg_chat_id)) == b"2":
        print("User " + str(msg_chat_id) + " is already blocked.")
        await message.reply(VERIF_FAIL.format(errcode=9001,botuser=pyroSecrets.PYRO_MY_BOTNAME))
        await client.block_user(msg_chat_id)
        return

    # automatically send captcha and delete all message before captcha finished
    #     if captcha is correct, add to k-v for bypass
    #     if incorrect, block directly
    if not message.outgoing:
        # check pmstat_ in redis
        pmstat = redis_cli.get("pmstat_" + str(msg_chat_id))
        # pmstat_ not found, means new pm, send captcha
        if pmstat is None:
            # send captcha
            sessionUUID = str(uuidgen())
            curTs = int(time.time()) + 95
            veriurl = pyroSecrets.WEB_HostName + "/show" + pyroSecrets.WEB_UrlPrefix + "/" \
                      + sessionUUID + "/" + str(msg_chat_id) + "/" + str(curTs)
            if message.from_user.is_verified:
                await message.reply("Premium User need to verify twice! (Just a joke)")
            await message.reply(VERIF_TMPL.format(veriurl=veriurl, botuser=pyroSecrets.PYRO_MY_BOTNAME, tsstr=time.strftime("%Y-%m-%d %H:%M:%S",
                                                                                       time.localtime(int(time.time())))))
            print("Captcha sent to " + str(msg_chat_id))
            # set pmstat_ and uinverify_ in redis
            ret = redis_cli.set("pmstat_" + str(msg_chat_id), curTs, ex=600)
            if ret is None:
                print("[ERROR] pmstat_" + str(msg_chat_id) + " set stat failed")
            ret = redis_cli.set("uinverify_" + str(msg_chat_id), sessionUUID + "," + str(curTs), ex=95)
            if ret is None:
                print("[ERROR] uinverify_" + str(msg_chat_id) + " set stat failed")
            return
        # pmstat_ found, means captcha already sent, check if sent sig is correct
        # if correct, add to k-v for bypass
        # first, check uinverify_ exists or not, if not, already expired
        # block user and return
        else:
            # check if value expired
            if int(pmstat.decode()) < int(time.time()):
                await message.reply(VERIF_FAIL.format(errcode=9002, botuser=pyroSecrets.PYRO_MY_BOTNAME))
                print("Captcha expired, block user " + str(msg_chat_id))
                await client.block_user(msg_chat_id)
                # set ulist_ in redis
                ret = redis_cli.set("ulist_" + str(msg_chat_id), 2)
                if ret is None:
                    print("[ERROR] ulist_" + str(msg_chat_id) + " set stat failed")
                return
            # check uinverify_ in redis
            uinverify = redis_cli.get("uinverify_" + str(msg_chat_id))
            if uinverify is None:
                # uinverify_ not found, already expired, block user and return
                await message.reply(VERIF_FAIL.format(errcode=9004, botuser=pyroSecrets.PYRO_MY_BOTNAME))
                await client.block_user(msg_chat_id)
                print("Captcha expired, block user " + str(msg_chat_id))
                ret = redis_cli.set("ulist_" + str(msg_chat_id), 2)
                if ret is None:
                    print("[ERROR] ulist_" + str(msg_chat_id) + " set block failed")
                return
            # uinverify_ found, check if sig is correct
            # if correct, add to k-v for bypass
            else:
                # retrieve text from message
                textSig = message.text
                userid = str(msg_chat_id)
                # retrieve ts from uinverify_
                # ts = [1], sessionUUID = [0]
                tsAndUUID = uinverify.decode().split(",")
                try:
                    oriSignTxt = tsAndUUID[0] + "/" + userid + "/" + tsAndUUID[1]
                except KeyError:
                    await message.reply(VERIF_500.format(errcode=9098, botuser=pyroSecrets.PYRO_MY_BOTNAME))
                    print("[ERROR] KeyError in uinverify_" + str(msg_chat_id))
                    return
                # generate sig
                secretKeyB64 = pyroSecrets.HMAC_KEY_B64_URLSAFE_NOPAD
                while len(secretKeyB64) % 4 != 0:
                    secretKeyB64 += "="
                secretKey = secretKeyB64.encode("utf-8")
                secretKeyBytes = base64.urlsafe_b64decode(secretKey)
                sigBytes = hmac.new(secretKeyBytes,
                                    oriSignTxt.encode(),
                                    hashlib.sha256)
                sigB64 = base64.b64encode(sigBytes.digest()).decode("utf-8")
                print("Debug Sig: " + sigB64)
                # compare sig
                if sigB64 == textSig:
                    print("Captcha correct, add to whitelist " + str(msg_chat_id))
                    # sig correct, add to k-v for bypass
                    ret = redis_cli.set("ulist_" + str(msg_chat_id), 1)
                    if ret is None:
                        print("[ERROR] ulist_" + str(msg_chat_id) + " set ok")
                        await message.reply(VERIF_500.format(errcode=9099))
                        return
                    else:
                        print("Verification Passed for: " + str(msg_chat_id))
                        await message.reply(VERIF_PASS)
                        return
                else:
                    # sig incorrect, block user and return
                    print("Captcha SIG incorrect, block user " + str(msg_chat_id))
                    await message.reply(VERIF_FAIL.format(errcode=9003, botuser=pyroSecrets.PYRO_MY_BOTNAME))
                    await client.block_user(msg_chat_id)
                    ret = redis_cli.set("ulist_" + str(msg_chat_id), 2)
                    if ret is None:
                        print("[ERROR] ulist_" + str(msg_chat_id) + " set block failed")
                    return


def main():
    # Connect to redis
    try:
        redis_cli.ping()
        print("Redis Connected.")
    except:
        print("Redis connection failed")
        sys.exit(1)


print("PyroPM Captcha Bot is starting...")
main()
app.run()
