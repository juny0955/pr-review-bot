import asyncio
import unittest


class IngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_incomplete_or_ambiguous_upstream_responses(self):
        import ingress
        responses = [b'HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\n\r\nx',
                     b'HTTP/1.1 202 Accepted\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx',
                     b'HTTP/1.1 202 Accepted\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n',
                     b'HTTP/1.1 202 Accepted\r\n\r\nx',
                     b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\nx']
        for response in responses:
            async def backend(reader, writer):
                await reader.readuntil(b'\r\n\r\n')
                writer.write(response); await writer.drain()
                writer.close(); await writer.wait_closed()
            upstream = await asyncio.start_server(backend, '127.0.0.1', 0)
            server = await ingress.start_server(port=0, upstream_port=upstream.sockets[0].getsockname()[1])
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
                writer.write(b'POST /webhook HTTP/1.1\r\nContent-Length: 0\r\n\r\n'); await writer.drain()
                self.assertTrue((await reader.read()).startswith(b'HTTP/1.1 502 '), response)
                writer.close(); await writer.wait_closed()
            finally:
                server.close(); upstream.close()
                await server.wait_closed(); await upstream.wait_closed()

    async def test_upstream_timeout_returns_504(self):
        import ingress
        done = asyncio.Event()
        async def backend(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            await reader.read()
            writer.close()
            await writer.wait_closed()
            done.set()
        upstream = await asyncio.start_server(backend, '127.0.0.1', 0)
        server = await ingress.start_server(port=0, upstream_port=upstream.sockets[0].getsockname()[1], deadline=.1)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(b'POST /webhook HTTP/1.1\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            self.assertTrue((await reader.read()).startswith(b'HTTP/1.1 504 '))
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(done.wait(), 1)
        finally:
            server.close(); upstream.close()
            await server.wait_closed(); await upstream.wait_closed()

    async def test_empty_upstream_returns_502(self):
        import ingress
        async def backend(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.close()
            await writer.wait_closed()
        upstream = await asyncio.start_server(backend, '127.0.0.1', 0)
        server = await ingress.start_server(port=0, upstream_port=upstream.sockets[0].getsockname()[1])
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(b'POST /webhook HTTP/1.1\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            self.assertTrue((await reader.read()).startswith(b'HTTP/1.1 502 '))
            writer.close()
            await writer.wait_closed()
        finally:
            server.close(); upstream.close()
            await server.wait_closed(); await upstream.wait_closed()

    async def test_upstream_connection_refused_returns_502(self):
        import ingress
        upstream = await asyncio.start_server(lambda r, w: None, '127.0.0.1', 0)
        port = upstream.sockets[0].getsockname()[1]
        upstream.close()
        await upstream.wait_closed()
        server = await ingress.start_server(port=0, upstream_port=port)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(b'POST /webhook HTTP/1.1\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            self.assertTrue((await reader.read()).startswith(b'HTTP/1.1 502 '))
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    async def test_signed_webhook_reaches_real_receiver(self):
        import hashlib, hmac, sqlite3, tempfile, threading
        from pathlib import Path
        from contextlib import closing
        import ingress
        import receiver
        from test_receiver import payload
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / 'queue.db')
            backend = receiver.create_server('secret', {123: 'acme/repo'}, db, port=0)
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            server = await ingress.start_server(port=0, upstream_port=backend.server_port)
            try:
                body = payload()
                signature = hmac.new(b'secret', body, hashlib.sha256).hexdigest().encode()
                reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
                writer.write(b'POST /webhook HTTP/1.1\r\nHost: localhost\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nX-Hub-Signature-256: sha256=' + signature + b'\r\nX-GitHub-Event: pull_request\r\nX-GitHub-Delivery: abc\r\n\r\n' + body)
                await writer.drain()
                self.assertIn(b'202', await reader.read())
                writer.close()
                with closing(sqlite3.connect(db)) as conn:
                    self.assertEqual(conn.execute('SELECT body FROM queue').fetchone()[0], body)
            finally:
                server.close(); await server.wait_closed()
                await asyncio.to_thread(backend.shutdown)
                backend.server_close(); thread.join()

    async def test_limits_body_and_ambiguous_framing(self):
        import ingress
        server = await ingress.start_server(port=0)
        try:
            port = server.sockets[0].getsockname()[1]
            for headers, status in [(b'Content-Length: 1048577', b'413'),
                                    (b'Content-Length: 1\r\nContent-Length: 1', b'400'),
                                    (b'Content-Length: 1\r\nTransfer-Encoding: chunked', b'400')]:
                reader, writer = await asyncio.open_connection('127.0.0.1', port)
                writer.write(b'POST /webhook HTTP/1.1\r\n' + headers + b'\r\n\r\n')
                await writer.drain()
                self.assertIn(status, await reader.read())
                writer.close()
        finally:
            server.close(); await server.wait_closed()

    async def test_connection_cap_and_absolute_deadline(self):
        import ingress
        server = await ingress.start_server(port=0, max_connections=1, deadline=.15)
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.write(b'POST /webhook HTTP/1.1\r\n'); await writer.drain()
            await asyncio.sleep(.02)
            reader2, writer2 = await asyncio.open_connection('127.0.0.1', port)
            self.assertEqual(await asyncio.wait_for(reader2.read(), .3), b'')
            await asyncio.sleep(.08)
            writer.write(b'Host: localhost\r\n'); await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), .3), b'')
            writer.close(); writer2.close()
        finally:
            server.close(); await server.wait_closed()

    async def test_global_connection_rate_limit(self):
        import ingress
        server = await ingress.start_server(port=0, rate=.01, burst=1)
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.write(b'GET / HTTP/1.1\r\n\r\n'); await writer.drain()
            self.assertIn(b'400', await reader.read())
            reader2, writer2 = await asyncio.open_connection('127.0.0.1', port)
            self.assertEqual(await reader2.read(), b'')
            writer.close(); writer2.close()
        finally:
            server.close(); await server.wait_closed()

    async def test_fragmented_upstream_response_is_not_truncated(self):
        import ingress
        async def backend(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 3\r\nConnection: close\r\n\r\n')
            await writer.drain()
            await asyncio.sleep(.05)
            writer.write(b'yes')
            await writer.drain()
            writer.close()
        upstream = await asyncio.start_server(backend, '127.0.0.1', 0)
        server = await ingress.start_server(upstream_port=upstream.sockets[0].getsockname()[1], port=0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(b'POST /webhook HTTP/1.1\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            self.assertTrue((await reader.read()).endswith(b'yes'))
            writer.close()
        finally:
            server.close(); upstream.close()
            await server.wait_closed(); await upstream.wait_closed()

    async def test_accepts_normal_connection_close_header(self):
        import ingress
        async def backend(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
            writer.close()
        upstream = await asyncio.start_server(backend, '127.0.0.1', 0)
        server = await ingress.start_server(upstream_port=upstream.sockets[0].getsockname()[1], port=0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(b'POST /webhook HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
            self.assertIn(b'202 Accepted', await reader.read())
            writer.close()
        finally:
            server.close()
            upstream.close()
            await server.wait_closed()
            await upstream.wait_closed()

    async def test_forwards_exact_body_and_response(self):
        import ingress
        received = []
        async def backend(reader, writer):
            headers = await reader.readuntil(b'\r\n\r\n')
            body = await reader.readexactly(3)
            received.append((headers, body))
            writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 3\r\nConnection: close\r\n\r\nyes')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        upstream = await asyncio.start_server(backend, '127.0.0.1', 0)
        server = await ingress.start_server(upstream_port=upstream.sockets[0].getsockname()[1], port=0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(b'POST /webhook HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nX-Hub-Signature-256: abc\r\n\r\na\x00b')
            await writer.drain()
            response = await reader.read()
            self.assertIn(b'202 Accepted', response)
            self.assertEqual(received[0][1], b'a\x00b')
            self.assertIn(b'X-Hub-Signature-256: abc', received[0][0])
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            upstream.close()
            await server.wait_closed()
            await upstream.wait_closed()
