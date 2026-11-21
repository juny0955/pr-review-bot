"""Explicitly invoked, channel-restricted Discord notification transport."""

import http.client
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NotificationError(Exception):
    """A Discord notification could not be delivered."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DiscordTransport:
    """Send only to one explicitly configured channel using a separate bot token.

    The opener is injectable for offline tests; the default refuses redirects so
    authorization headers cannot be forwarded to another endpoint.
    """

    def __init__(self, channel, *, environ=None, open_request=None, timeout=10):
        if not isinstance(channel, str) or not channel.isascii() or not channel.isdecimal() or not 0 < len(channel) <= 20:
            raise ValueError('invalid channel')
        token = (os.environ if environ is None else environ).get('DISCORD_BOT_TOKEN')
        if not isinstance(token, str) or not token or not token.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in token):
            raise ValueError('invalid Discord bot token')
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 60:
            raise ValueError('invalid timeout')
        self._channel = channel
        self._token = token
        self._open = open_request if open_request is not None else build_opener(_NoRedirect()).open
        self._timeout = timeout

    def __call__(self, channel, payload):
        if channel != self._channel:
            raise ValueError('channel not allowed')
        if (not isinstance(payload, dict) or set(payload) != {'content', 'allowed_mentions'}
                or payload['allowed_mentions'] != {'parse': []}
                or not isinstance(payload['content'], str) or not payload['content'].strip()
                or len(payload['content']) > 2000):
            raise ValueError('invalid notification')
        request = Request(
            f'https://discord.com/api/v10/channels/{self._channel}/messages',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Authorization': f'Bot {self._token}', 'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with self._open(request, timeout=self._timeout) as response:
                if not 200 <= response.status < 300:
                    raise NotificationError('Discord notification failed')
        except HTTPError as error:
            error.close()
            raise NotificationError('Discord notification failed') from None
        except (URLError, TimeoutError, OSError, http.client.HTTPException):
            raise NotificationError('Discord notification failed') from None

class DiscordNotifier:
    def __init__(self, allowed_channels, send, *, enabled=False):
        if type(enabled) is not bool:
            raise ValueError('enabled must be boolean')
        if isinstance(allowed_channels, (str, bytes)):
            raise ValueError('invalid channel allowlist')
        self.allowed_channels = frozenset(allowed_channels)
        if not all(isinstance(c, str) and c.isascii() and c.isdecimal() and 0 < len(c) <= 20 for c in self.allowed_channels):
            raise ValueError('invalid channel allowlist')
        self.send = send
        self.enabled = enabled

    def notify(self, channel, content):
        if channel not in self.allowed_channels:
            raise ValueError('channel not allowed')
        if not isinstance(content, str) or not content.strip() or len(content) > 2000:
            raise ValueError('invalid notification')
        if not self.enabled:
            return 'dry_run'
        self.send(channel, {'content': content, 'allowed_mentions': {'parse': []}})
        return 'sent'
