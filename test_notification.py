import unittest
from unittest.mock import Mock
from notification import DiscordNotifier


class NotificationTests(unittest.TestCase):
    def test_default_is_dry_run(self):
        send = Mock()
        self.assertEqual(DiscordNotifier({'123'}, send).notify('123', 'hello'), 'dry_run')
        send.assert_not_called()

    def test_enabled_sends_only_to_allowlisted_channel_with_mentions_disabled(self):
        send = Mock()
        notifier = DiscordNotifier({'123'}, send, enabled=True)
        self.assertEqual(notifier.notify('123', 'hello @everyone'), 'sent')
        send.assert_called_once_with('123', {'content': 'hello @everyone', 'allowed_mentions': {'parse': []}})

    def test_bad_inputs_and_implicit_enable_rejected(self):
        send = Mock()
        with self.assertRaises(ValueError):
            DiscordNotifier({'123'}, send, enabled='false')
        notifier = DiscordNotifier({'123'}, send, enabled=True)
        for channel, content in [('456', 'hello'), ('123', ''), ('123', 'x' * 2001)]:
            with self.subTest(channel=channel, length=len(content)), self.assertRaises(ValueError):
                notifier.notify(channel, content)
        send.assert_not_called()
