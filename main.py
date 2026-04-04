#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import base64
import binascii
import hashlib
import hmac
import logging
import time
import uuid

import redis.asyncio as redis
from telethon import TelegramClient, events
from telethon.tl.functions.contacts import BlockRequest

from teleSecrets import (
	DB_REDIS_DB,
	DB_REDIS_IP,
	DB_REDIS_PASS,
	DB_REDIS_PORT,
	DB_REDIS_USER,
	HMAC_KEY_B64_URLSAFE_NOPAD,
	TELE_API_ID,
	TELE_API_SECRET,
	TELE_MY_BOTNAME,
	TELE_MY_TITLE,
	WEB_HostName,
	WEB_UrlPrefix,
)


VERIFY_TTL_SECONDS = 300
PMSTAT_TTL_SECONDS = 600
VERIFY_RESULT_MAX_AGE_SECONDS = 45
SESSION_NAME = "pmcaptcha_myoungram"

ERR_ALREADY_BLOCKED = 9001
ERR_PENDING_EXPIRED = 9002
ERR_SIGNATURE_FAILED = 9003
ERR_RESULT_TOO_OLD = 9004
ERR_DATABASE = 9099
ERR_PYTHON = 9098

STATE_ALLOWED = "1"
STATE_BLOCKED = "2"
STATE_WAITING = "3"

logger = logging.getLogger("pmcaptcha")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] - [%(levelname)s] : %(message)s")
handler.setFormatter(formatter)
if not logger.handlers:
	logger.addHandler(handler)
logger.propagate = False

logging.getLogger('telethon').setLevel(level=logging.WARNING)


def log_user_action(action: str, chat_id: int | None, user_id: int | None, **context) -> None:
	ctx = " ".join(f"{k}={context[k]!r}" for k in sorted(context))
	if ctx:
		logger.info("action=%s chat_id=%s user_id=%s %s", action, chat_id, user_id, ctx)
		return
	logger.info("action=%s chat_id=%s user_id=%s", action, chat_id, user_id)


redis_client = redis.Redis(
	host=DB_REDIS_IP,
	port=DB_REDIS_PORT,
	username=DB_REDIS_USER,
	password=DB_REDIS_PASS,
	db=DB_REDIS_DB,
	decode_responses=True,
)

client = TelegramClient(SESSION_NAME, int(TELE_API_ID), TELE_API_SECRET)


def b64url_decode_nopad(value: str) -> bytes:
	padding = "=" * (-len(value) % 4)
	return base64.urlsafe_b64decode(value + padding)


def b64url_encode_nopad(value: bytes) -> str:
	return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def redis_key_allow(chat_id: int) -> str:
	return f"ulist_{chat_id}"


def redis_key_pending(chat_id: int) -> str:
	return f"pmstat_{chat_id}"


def redis_key_verify(chat_id: int) -> str:
	return f"uinverify_{chat_id}"


ALLOW_IF_NOT_BLOCKED_LUA = """
local current = redis.call('GET', KEYS[1])
if current == '2' then
  return 0
end
redis.call('SET', KEYS[1], '1')
return 1
"""


async def mark_allowed_unless_blocked(chat_id: int) -> bool:
	allow_key = redis_key_allow(chat_id)
	result = await redis_client.eval(ALLOW_IF_NOT_BLOCKED_LUA, 1, allow_key)
	return bool(result)


SET_WAITING_IF_NOT_BLOCKED_LUA = """
local current = redis.call('GET', KEYS[1])
if current == '2' then
  return 0
end
if current == '1' then
	return 1
end
redis.call('SET', KEYS[1], '3')
return 1
"""


async def mark_waiting_unless_blocked(user_id: int) -> bool:
	allow_key = redis_key_allow(user_id)
	result = await redis_client.eval(SET_WAITING_IF_NOT_BLOCKED_LUA, 1, allow_key)
	return bool(result)


async def clear_pending_verification(chat_id: int) -> None:
	try:
		await redis_client.delete(redis_key_pending(chat_id), redis_key_verify(chat_id))
	except redis.RedisError:
		raise


def build_verify_url(session_uuid: str, user_id: int, current_ts: int) -> str:
	return f"{WEB_HostName}/show{WEB_UrlPrefix}/{session_uuid}/{user_id}/{current_ts}"


def hmac_signature(payload: str) -> str:
	key_bytes = b64url_decode_nopad(HMAC_KEY_B64_URLSAFE_NOPAD)
	sig = hmac.new(key_bytes, payload.encode("utf-8"), hashlib.sha256).digest()
	return b64url_encode_nopad(sig)


def parse_verify_token(token: str) -> tuple[str, str, int]:
	decoded = b64url_decode_nopad(token.strip()).decode("utf-8")
	payload, sig = decoded.rsplit("/", 1)
	expected = hmac_signature(payload)
	if not hmac.compare_digest(sig, expected):
		raise ValueError("signature mismatch")

	session_uuid, user_id, ts_text = payload.split("/", 2)
	return session_uuid, user_id, int(ts_text)


async def block_user(user_id: int) -> None:
	log_user_action("block_initiated", None, user_id)
	try:
		peer = await client.get_input_entity(user_id)
		await client(BlockRequest(peer))
		log_user_action("block_succeeded", None, user_id)
	except Exception as exc:  # pragma: no cover
		log_user_action("block_failed", None, user_id, error=str(exc))
		logger.warning("Failed to block user %s: %s", user_id, exc)


async def fail_and_block(event: events.NewMessage.Event, err_code: int, text: str) -> None:
	log_user_action(
		"blocked_due_to_error",
		event.chat_id,
		event.sender_id,
		err_code=err_code,
		reason=text,
	)
	logger.warning(
		"Fail-and-block err=%s chat_id=%s user_id=%s detail=%s message=%r",
		err_code,
		event.chat_id,
		event.sender_id,
		text,
		event.raw_text,
	)
	await event.reply(
		f"Error occurred (ErrCode {err_code}).\n"
		f"For assistance, copy this error code and contact {TELE_MY_BOTNAME}."
	)
	try:
		await redis_client.set(redis_key_allow(event.sender_id), STATE_BLOCKED)
	except redis.RedisError as exc:
		logger.error("Redis failure while blocking chat %s: %s", event.chat_id, exc)
	await block_user(event.sender_id)


async def reply_error(event: events.NewMessage.Event, err_code: int, text: str) -> None:
	log_user_action(
		"error_reported",
		event.chat_id,
		event.sender_id,
		err_code=err_code,
		reason=text,
	)
	logger.warning(
		"Reply error err=%s chat_id=%s user_id=%s detail=%s message=%r",
		err_code,
		event.chat_id,
		event.sender_id,
		text,
		event.raw_text,
	)
	await event.reply(
		f"Error occurred (ErrCode {err_code}).\n"
		f"For assistance, copy this error code and contact {TELE_MY_BOTNAME}."
	)


@client.on(events.NewMessage(incoming=True))
async def pm_guard(event: events.NewMessage.Event) -> None:
	if not event.is_private:
		return
	if event.message.action is not None:
		return

	chat_id = event.chat_id
	user_id = event.sender_id
	sender = await event.get_sender()
	if sender is None:
		log_user_action("incoming_sender_missing", chat_id, user_id)
		return

	# incoming message is from a bot, not required to verify
	if getattr(sender, "bot", False):
		return

	# Skip your own outgoing messages mirrored in saved/private contexts.
	if getattr(sender, "is_self", False):
		return

	allow_key = redis_key_allow(user_id)
	pending_key = redis_key_pending(chat_id)
	verify_key = redis_key_verify(chat_id)

	try:
		allow_state = await redis_client.get(allow_key)
	except redis.RedisError as exc:
		logger.error("Redis read failed on %s: %s", allow_key, exc)
		await reply_error(event, ERR_DATABASE, "Database read failure.")
		return

	if allow_state == STATE_BLOCKED:
		log_user_action("incoming_user_already_blocked", chat_id, user_id)
		await reply_error(event, ERR_ALREADY_BLOCKED, "Already blocked previously.")
		await block_user(sender.id)
		return

	if allow_state == STATE_ALLOWED:
		return

	if getattr(sender, "contact", False) or getattr(sender, "mutual_contact", False):
		try:
			allowed = await mark_allowed_unless_blocked(user_id)
		except redis.RedisError as exc:
			logger.error("Redis write failed on %s: %s", allow_key, exc)
		return

	raw_text = (event.raw_text or "").strip()
	if allow_state == STATE_WAITING and not raw_text.startswith("/verify "):
		log_user_action("waiting_received_non_verify", chat_id, user_id, message=raw_text)
		await fail_and_block(
			event,
			ERR_SIGNATURE_FAILED,
			"Unexpected message while waiting for verification."
		)
		return

	if raw_text.startswith("/verify "):
		log_user_action("verify_command_received", chat_id, user_id)
		token = raw_text.split(" ", 1)[1].strip()
		if not token:
			log_user_action("verify_command_missing_payload", chat_id, user_id)
			await reply_error(event, ERR_SIGNATURE_FAILED, "Missing verification payload.")
			return

		try:
			pending_ts_raw = await redis_client.get(pending_key)
			verify_raw = await redis_client.get(verify_key)
		except redis.RedisError as exc:
			logger.error("Redis read failed for pending verification: %s", exc)
			await reply_error(event, ERR_DATABASE, "Database read failure.")
			return

		if allow_state == STATE_WAITING and not pending_ts_raw:
			log_user_action("waiting_pmstat_missing", chat_id, user_id)
			await fail_and_block(event, ERR_PENDING_EXPIRED, "Verification session record missing.")
			return

		if not pending_ts_raw or not verify_raw:
			log_user_action("verify_session_missing", chat_id, user_id)
			await fail_and_block(event, ERR_PENDING_EXPIRED, "No active verification session.")
			return

		try:
			session_uuid_expected, _created_ts, _remote_ip = verify_raw.split(",", 2
			)
			created_ts = int(_created_ts)
			session_uuid_recv, user_id_recv, result_ts = parse_verify_token(token)
			now = int(time.time())
		except (ValueError, TypeError, binascii.Error):
			await fail_and_block(event, ERR_SIGNATURE_FAILED, "Signature verification failed.")
			return
		except Exception as exc:  # pragma: no cover
			logger.exception("Token parsing exception: %s", exc)
			await fail_and_block(event, ERR_PYTHON, "Unexpected runtime error.")
			return

		if now - created_ts > VERIFY_TTL_SECONDS:
			log_user_action("verify_expired", chat_id, user_id, age_seconds=now - created_ts)
			await fail_and_block(event, ERR_PENDING_EXPIRED, "Verification session expired.")
			return

		if now - result_ts > VERIFY_RESULT_MAX_AGE_SECONDS:
			log_user_action("verify_result_too_old", chat_id, user_id, age_seconds=now - result_ts)
			await fail_and_block(event, ERR_RESULT_TOO_OLD, "Verification result is too old.")
			return

		if session_uuid_recv != session_uuid_expected or user_id_recv != str(sender.id):
			log_user_action("verify_session_mismatch", chat_id, user_id)
			await fail_and_block(event, ERR_SIGNATURE_FAILED, "Session mismatch.")
			return

		try:
			if not await mark_allowed_unless_blocked(user_id):
				log_user_action("verify_finalize_blocked", chat_id, user_id)
				await reply_error(event, ERR_ALREADY_BLOCKED, "Blocked state while finalizing verification.")
				await block_user(sender.id)
				return
			await redis_client.delete(pending_key, verify_key)
		except redis.RedisError as exc:
			logger.error("Redis write failure finalizing verification: %s", exc)
			await reply_error(event, ERR_DATABASE, "Database write failure.")
			return

		log_user_action("verification_passed", chat_id, user_id)
		await event.reply("Verification succeeded. You can now message me.")
		return

	session_uuid = str(uuid.uuid4())
	now = int(time.time())

	try:
		if not await mark_waiting_unless_blocked(user_id):
			log_user_action("verification_trigger_denied_blocked", chat_id, user_id)
			await reply_error(event, ERR_ALREADY_BLOCKED, "Already blocked previously.")
			await block_user(sender.id)
			return
		await redis_client.set(pending_key, str(now), ex=PMSTAT_TTL_SECONDS)
		await redis_client.set(verify_key, f"{session_uuid},{now},-", ex=VERIFY_TTL_SECONDS)
	except redis.RedisError as exc:
		logger.error("Redis write failed for chat %s: %s", chat_id, exc)
		await reply_error(event, ERR_DATABASE, "Database write failure.")
		return

	verify_url = build_verify_url(session_uuid, sender.id, now)
	log_user_action("verification_triggered", chat_id, user_id)
	await event.reply(
		"Anti-spam verification required.\n"
		f"1) Open [here to verify]({verify_url})\n"
		"2) Finish the captcha\n"
		"3) Copy token and send:\n"
		"/verify <TOKEN>\n"
		"This request expires in 5 minutes.",
		parse_mode="md"
	)


@client.on(events.NewMessage(outgoing=True))
async def allow_on_outgoing_pm(event: events.NewMessage.Event) -> None:
	if not event.is_private:
		return
	if event.message.action is not None:
		return

	chat_id = event.chat_id
	peer_user_id = event.chat_id
	if not chat_id:
		return

	try:
		allowed = await mark_allowed_unless_blocked(peer_user_id)
		if allowed:
			await clear_pending_verification(chat_id)
	except redis.RedisError as exc:
		logger.error("Redis write failed while allowing outgoing chat %s: %s", chat_id, exc)


async def main() -> None:
	try:
		await redis_client.ping()
	except redis.RedisError as exc:
		logger.error("Unable to connect to Redis: %s", exc)
		raise

	await client.start()
	me = await client.get_me()
	logger.info("%s online as @%s (%s)", TELE_MY_TITLE, me.username, me.id)
	await client.run_until_disconnected()


if __name__ == "__main__":
	asyncio.run(main())
