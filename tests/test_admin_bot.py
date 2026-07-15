import unittest

from admin_panel.bot import (
    AdminTelegramBot,
    CommandError,
    CreateCommand,
    PendingActions,
    parse_account_ids,
    parse_allowed_user_ids,
    parse_create_command,
)


class ParserTests(unittest.TestCase):
    def test_allowed_user_ids_are_trimmed_and_deduped(self):
        self.assertEqual(parse_allowed_user_ids(" 10,20,10 "), {10, 20})

    def test_allowed_user_ids_are_required(self):
        with self.assertRaises(Exception):
            parse_allowed_user_ids(" , ")

    def test_account_ids_support_ranges_and_dedupe(self):
        self.assertEqual(parse_account_ids("1, 3-5,4,7"), [1, 3, 4, 5, 7])

    def test_account_ids_cap_at_100(self):
        with self.assertRaises(CommandError):
            parse_account_ids("1-101")

    def test_create_command_parses_country_os_and_ids(self):
        command = parse_create_command("/create Mozambique Windows 1-3,8")
        self.assertEqual(command, CreateCommand("mz", "win", [1, 2, 3, 8]))


class PendingActionTests(unittest.TestCase):
    def test_pending_action_expires_and_is_user_scoped(self):
        pending = PendingActions(ttl_seconds=5)
        token = pending.add(10, "create", {"account_ids": [1]}, now=100.0)
        self.assertIsNone(pending.pop(token, 11, now=101.0))
        self.assertIsNotNone(pending.pop(token, 10, now=101.0))
        token = pending.add(10, "create", {"account_ids": [1]}, now=100.0)
        self.assertIsNone(pending.pop(token, 10, now=106.0))

    def test_pending_action_can_be_popped_once(self):
        pending = PendingActions(ttl_seconds=5)
        token = pending.add(10, "create", {"account_ids": [1]}, now=100.0)
        item = pending.pop(token, 10, now=101.0)
        self.assertIsNotNone(item)
        self.assertEqual(item.payload["account_ids"], [1])
        self.assertIsNone(pending.pop(token, 10, now=101.0))


class FakeTelegram:
    def __init__(self):
        self.messages = []
        self.callbacks = []
        self.edits = []

    def send_message(self, chat_id, text, reply_markup=None):
        self.messages.append((chat_id, text, reply_markup))

    def answer_callback(self, callback_query_id, text=""):
        self.callbacks.append((callback_query_id, text))

    def edit_message(self, chat_id, message_id, text):
        self.edits.append((chat_id, message_id, text))


class FakeBackend:
    def __init__(self):
        self.created = []

    def create_job(self, command):
        self.created.append(command)
        return 42


class BotCommandTests(unittest.TestCase):
    def test_create_requires_inline_confirmation_before_backend_post(self):
        telegram = FakeTelegram()
        backend = FakeBackend()
        bot = AdminTelegramBot(telegram, backend, {10})

        bot.handle_message(
            {
                "chat": {"id": 100, "type": "private"},
                "from": {"id": 10},
                "text": "/create mz win 1-2",
            }
        )

        self.assertEqual(backend.created, [])
        markup = telegram.messages[0][2]
        callback_data = markup["inline_keyboard"][0][0]["callback_data"]
        bot.handle_callback(
            {
                "id": "cb1",
                "from": {"id": 10},
                "data": callback_data,
                "message": {"chat": {"id": 100, "type": "private"}, "message_id": 5},
            }
        )

        self.assertEqual(len(backend.created), 1)
        self.assertEqual(backend.created[0].account_ids, [1, 2])
        self.assertEqual(telegram.edits, [(100, 5, "Job #42 started.")])

    def test_unauthorized_user_is_rejected(self):
        telegram = FakeTelegram()
        bot = AdminTelegramBot(telegram, FakeBackend(), {10})

        bot.handle_message({"chat": {"id": 100, "type": "private"}, "from": {"id": 11}, "text": "/status"})

        self.assertEqual(telegram.messages, [(100, "Unauthorized.", None)])


if __name__ == "__main__":
    unittest.main()
