"""Explicitly invoked Discord notification adapter; no transport is installed."""

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
