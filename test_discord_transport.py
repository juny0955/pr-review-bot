import json
import http.client
import traceback
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

from notification import DiscordTransport, NotificationError, DiscordNotifier


class DiscordTransportTests(unittest.TestCase):
    def test_posts_bot_message_to_configured_channel(self):
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock(return_value=response)
        transport = DiscordTransport('123', environ={'DISCORD_BOT_TOKEN': 'secret'}, open_request=opener)
        self.assertEqual(DiscordNotifier({'123'}, transport, enabled=True).notify('123', 'hello'), 'sent')
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, 'https://discord.com/api/v10/channels/123/messages')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.get_header('Authorization'), 'Bot secret')
        self.assertEqual(request.get_header('User-agent'), 'PRReviewBot/1.0')
        self.assertEqual(request.get_header('Content-type'), 'application/json')
        self.assertEqual(json.loads(request.data), {'content': 'hello', 'allowed_mentions': {'parse': []}})
        self.assertGreater(opener.call_args.kwargs['timeout'], 0)

    def test_transport_restricts_channel_payload_and_credentials(self):
        opener = Mock()
        for token in ('', 'bad\nheader'):
            with self.assertRaises(ValueError):
                DiscordTransport('123', environ={'DISCORD_BOT_TOKEN': token}, open_request=opener)
        for channel in ('', '../123', '１２３'):
            with self.assertRaises(ValueError):
                DiscordTransport(channel, environ={'DISCORD_BOT_TOKEN': 'secret'}, open_request=opener)
        transport = DiscordTransport('123', environ={'DISCORD_BOT_TOKEN': 'secret'}, open_request=opener)
        for channel, payload in [('456', {'content': 'hi', 'allowed_mentions': {'parse': []}}), ('123', {'content': 'hi'}), ('123', {'content': '@everyone', 'allowed_mentions': {'parse': ['everyone']}})]:
            with self.assertRaises(ValueError):
                transport(channel, payload)
        opener.assert_not_called()

    def test_errors_are_sanitized_and_not_reported_as_sent(self):
        for error in (URLError('secret'), HTTPError('https://secret', 429, 'secret', {}, None), TimeoutError('secret')):
            opener = Mock(side_effect=error)
            notifier = DiscordNotifier({'123'}, DiscordTransport('123', environ={'DISCORD_BOT_TOKEN': 'secret'}, open_request=opener), enabled=True)
            with self.assertRaises(NotificationError) as caught:
                notifier.notify('123', 'hello')
            self.assertNotIn('secret', str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)

    def test_other_responses_keep_existing_behavior(self):
        for status in (204, 299, 300, 403, 500):
            with self.subTest(status=status):
                response = Mock(status=status)
                response.__enter__ = Mock(return_value=response)
                response.__exit__ = Mock(return_value=False)
                transport = DiscordTransport('123', environ={'DISCORD_BOT_TOKEN': 'secret'}, open_request=Mock(return_value=response))
                notifier = DiscordNotifier({'123'}, transport, enabled=True)
                if status < 300:
                    self.assertEqual(notifier.notify('123', 'hello'), 'sent')
                else:
                    with self.assertRaises(NotificationError) as caught:
                        notifier.notify('123', 'hello')
                    self.assertEqual(str(caught.exception), 'Discord notification failed')
                    self.assertNotIn('secret', ''.join(traceback.format_exception(caught.exception)))

    def test_http_protocol_errors_are_sanitized(self):
        for error in (http.client.BadStatusLine('secret'), http.client.IncompleteRead(b'secret')):
            with self.subTest(error=type(error).__name__):
                opener = Mock(side_effect=error)
                transport = DiscordTransport('123', environ={'DISCORD_BOT_TOKEN': 'secret'}, open_request=opener)
                with self.assertRaises(NotificationError) as caught:
                    DiscordNotifier({'123'}, transport, enabled=True).notify('123', 'hello')
                self.assertEqual(str(caught.exception), 'Discord notification failed')
                self.assertNotIn('secret', ''.join(traceback.format_exception(caught.exception)))
