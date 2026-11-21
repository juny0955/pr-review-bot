"""Bounded loopback HTTP webhook proxy. Not a TLS terminator.

Upstream failures return 502 where possible, or 504 on upstream deadline.
This cannot tell whether a timed-out receiver already committed a delivery;
retries rely on receiver deduplication. Client failures may close silently.
"""
import asyncio
import re
import time

MAX_BODY = 1024 * 1024
MAX_HEADERS = 16384
MAX_RESPONSE = 65536


async def start_server(*, upstream_port=8080, port=8081, max_connections=32,
                       rate=10, burst=30, deadline=15):
    if not (0 <= port <= 65535 and 1 <= upstream_port <= 65535 and
            max_connections >= 1 and rate > 0 and burst >= 1 and deadline > 0):
        raise ValueError('invalid ingress configuration')
    active = 0
    tokens = float(burst)
    last = time.monotonic()

    async def respond(writer, status):
        writer.write(f'HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode())
        await writer.drain()

    async def exchange(reader, writer, phase):
        try:
            raw = await reader.readuntil(b'\r\n\r\n')
            if len(raw) > MAX_HEADERS:
                return await respond(writer, '431 Request Header Fields Too Large')
            lines = raw[:-4].split(b'\r\n')
            if lines[0] != b'POST /webhook HTTP/1.1':
                return await respond(writer, '400 Bad Request')
            headers = []
            for line in lines[1:]:
                if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*", line):
                    return await respond(writer, '400 Bad Request')
                name, value = line.split(b':', 1)
                headers.append((name.lower(), value.strip()))
            lengths = [v for n, v in headers if n == b'content-length']
            if (len(lengths) != 1 or not re.fullmatch(rb'[0-9]{1,8}', lengths[0]) or
                any(n in (b'transfer-encoding', b'expect', b'proxy-connection', b'upgrade') or
                    (n == b'connection' and v.lower() not in (b'close', b'keep-alive')) for n, v in headers)):
                return await respond(writer, '400 Bad Request')
            length = int(lengths[0])
            if length > MAX_BODY:
                return await respond(writer, '413 Payload Too Large')
            body = await reader.readexactly(length)
            phase.append(True)
            try:
                upstream_reader, upstream_writer = await asyncio.open_connection('127.0.0.1', upstream_port, limit=MAX_HEADERS)
            except OSError:
                return await respond(writer, '502 Bad Gateway')
            try:
                clean_headers = b'\r\n'.join(line for line in lines[1:] if not line.lower().startswith(b'connection:'))
                upstream_writer.write(lines[0] + b'\r\n' + clean_headers + b'\r\nConnection: close\r\n\r\n' + body)
                await upstream_writer.drain()
                response = bytearray()
                while True:
                    part = await upstream_reader.read(min(8192, MAX_RESPONSE + 1 - len(response)))
                    if not part:
                        break
                    response.extend(part)
                    if len(response) > MAX_RESPONSE:
                        return await respond(writer, '502 Bad Gateway')
                head, sep, response_body = bytes(response).partition(b'\r\n\r\n')
                response_lines = head.split(b'\r\n')
                if (not sep or len(head) + 4 > MAX_HEADERS or
                    not re.fullmatch(rb'HTTP/1\.[01] [2-5][0-9]{2} [\x20-\x7e]*', response_lines[0]) or
                    any(not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*", line) for line in response_lines[1:])):
                    return await respond(writer, '502 Bad Gateway')
                response_headers = [line.split(b':', 1) for line in response_lines[1:]]
                lengths = [v.strip() for n, v in response_headers if n.lower() == b'content-length']
                # ponytail: only fixed-length upstream responses; use a full HTTP proxy for chunked framing.
                if (any(n.lower() == b'transfer-encoding' for n, _ in response_headers) or
                    len(lengths) != 1 or not re.fullmatch(rb'[0-9]{1,8}', lengths[0]) or
                    int(lengths[0]) != len(response_body)):
                    return await respond(writer, '502 Bad Gateway')
                writer.write(response)
                await writer.drain()
            except (OSError, ConnectionError):
                return await respond(writer, '502 Bad Gateway')
            finally:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except OSError:
                    pass
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            await respond(writer, '400 Bad Request')
        except (OSError, ConnectionError):
            pass

    def accept(reader, writer):
        nonlocal active, tokens, last
        now = time.monotonic()
        tokens = min(float(burst), tokens + (now - last) * rate)
        last = now
        if active >= max_connections or tokens < 1:
            writer.close()
            return
        active += 1
        tokens -= 1

        async def run():
            nonlocal active
            phase = []
            try:
                await asyncio.wait_for(exchange(reader, writer, phase), deadline)
            except asyncio.TimeoutError:
                if phase:
                    try:
                        await asyncio.wait_for(respond(writer, '504 Gateway Timeout'), 1)
                    except (asyncio.TimeoutError, OSError, ConnectionError):
                        pass
            except (OSError, ConnectionError):
                pass
            finally:
                writer.close()
                active -= 1
        asyncio.create_task(run())

    return await asyncio.start_server(accept, '127.0.0.1', port, limit=MAX_HEADERS)


async def main():
    server = await start_server()
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
