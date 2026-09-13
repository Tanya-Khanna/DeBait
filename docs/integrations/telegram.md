# Telegram controlled-chat boundary

DeBait has a narrow Telegram Bot API adapter for one opted-in test chat. The running application does not enable it yet, and no bot account, group permissions or live Telegram action has been verified.

The adapter accepts only numeric resource identities created by DeBait: `message:<chat_id>:<message_id>` for deletion and `member:<chat_id>:<user_id>` for a chat ban. The configured bot ID must match both the token prefix and `getMe`. Chats and controlled test-attacker IDs are allowlisted before any HTTP request. Protected owner IDs must be configured separately and cannot overlap the attacker allowlist. The adapter exposes no send-message, invite, promotion, global-account block or arbitrary Bot API method.

Telegram's [Bot API reference](https://core.telegram.org/bots/api) says `deleteMessage` returns `True` on success, while `getChatMember` returns current membership. DeBait therefore treats deletion as acknowledged until a separately recorded Telegram-client observation confirms that the exact message is absent. A ban becomes verified only when `getChatMember` reports the designated controlled actor as `kicked`. “Banned” means excluded from the controlled demonstration chat, not blocked across Telegram.

The adapter asks for `revoke_messages=false`, but Telegram documents that message revocation is always enabled for bans in supergroups and channels. The test attacker must therefore have no unrelated history in the demonstration group. Other users and unrelated conversations remain out of scope.

The current message observation cache is a local adapter slice. Authenticated update ingestion, durable evidence storage, webhook-secret validation, bot administrator-right checks and native-client proof capture remain required before the live smoke test.
