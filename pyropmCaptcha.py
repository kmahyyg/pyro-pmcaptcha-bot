#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# pip3 install -U tgcrypto pyrogram uvloop ecdsa[gmpy2]

import pyroSecrets
import platform
import asyncio
import uvloop
from pyrogram import Client
from pyrogram import filters
import pickle

uvloop.install()

app = Client(name="pmcaptcha_my", 
    api_id=pyroSecrets.PYRO_API_ID, 
    api_hash=pyroSecrets.PYRO_API_SECRET,
    app_version=pyroSecrets.PYRO_MY_TITLE + " v1.0",
    device_model=platform.node())


@app.on_message(filters=filters.private)
async def captcha_pm(client, message):
    # If message is outgoing, means already known, add to k-v for bypass

    # if message is incoming and cannot find chat_id before, means new user
    #       automatically send captcha and delete all message before captcha finished
    #       if captcha is correct, add to k-v for bypass
    #           if incorrect, block directly

    # if message is incoming and can find chat_id before, means known user
    #
    #
    
    return


async def main():
    async with app:
        await app.start()
        await app.send_message("me", "hello")
        await app.stop()



asyncio.run(main())