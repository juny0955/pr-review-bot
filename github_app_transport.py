"""Explicit GitHub.com HTTPS transports; never log credentials or responses."""
import http.client
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time

MAX_REQUEST = 8192
MAX_RESPONSE = 256 * 1024
TIMEOUT = 15
_TOKEN = re.compile(r'[\x21-\x7e]{1,4096}\Z')
_PATH = re.compile(r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pulls/[1-9][0-9]*\Z')


def _https(method, path, credential, body):
    conn = http.client.HTTPSConnection('api.github.com', timeout=TIMEOUT)
    try:
        headers = {'Authorization': 'Bearer ' + credential, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'pr-review-bot'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError('HTTP failure')
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError('response too large')
        obj = json.loads(data)
        if not isinstance(obj, dict):
            raise ValueError('invalid response')
        return data
    finally:
        conn.close()


def _child():
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            return 1
        request = json.loads(raw)
        data = _https(request['method'], request['path'], request['credential'], request['body'])
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1


def _request(method, path, credential, body=None):
    try:
        if not isinstance(credential, str) or not _TOKEN.fullmatch(credential):
            raise ValueError('invalid credential')
        if body is not None and not isinstance(body, dict):
            raise ValueError('invalid body')
        encoded_body = None if body is None else json.dumps(body, separators=(',', ':'), allow_nan=False)
        payload = json.dumps({'method': method, 'path': path, 'credential': credential, 'body': encoded_body},
                             separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(payload) > MAX_REQUEST:
            raise ValueError('request too large')
        deadline = time.monotonic() + TIMEOUT
        proc = subprocess.Popen([sys.executable, '-I', '-S', os.path.abspath(__file__)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True, close_fds=True,
                                env={'PATH': os.defpath, 'LC_ALL': 'C'})
        try:
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                os.set_blocking(proc.stdin.fileno(), False)
                os.set_blocking(proc.stdout.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE)
                selector.register(proc.stdout, selectors.EVENT_READ)
                sent = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    for key, _ in selector.select(remaining):
                        if key.fileobj is proc.stdin:
                            sent += os.write(proc.stdin.fileno(), payload[sent:])
                            if sent == len(payload):
                                selector.unregister(proc.stdin)
                                proc.stdin.close()
                        else:
                            chunk = os.read(proc.stdout.fileno(), min(65536, MAX_RESPONSE + 1 - len(output)))
                            if not chunk:
                                selector.unregister(proc.stdout)
                            else:
                                output.extend(chunk)
                                if len(output) > MAX_RESPONSE:
                                    raise ValueError('response too large')
            # Keep the leader unreaped until group cleanup, avoiding PID reuse.
            while True:
                status = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if status is not None:
                    if status.si_code != os.CLD_EXITED or status.si_status != 0:
                        raise ValueError('child failed')
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                time.sleep(min(0.01, remaining))
            result = json.loads(output)
            if not isinstance(result, dict):
                raise ValueError('invalid response')
            return result
        finally:
            # ponytail: group termination is best effort; permission failures can leave descendants alive.
            cleanup_failed = False
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                cleanup_failed = True
                try:
                    proc.kill()
                except Exception:
                    pass
            for stream in (proc.stdin, proc.stdout):
                try:
                    stream.close()
                except Exception:
                    cleanup_failed = True
            try:
                proc.wait(timeout=1)
            except Exception:
                cleanup_failed = True
            if cleanup_failed:
                raise RuntimeError('cleanup failed')
    except Exception:
        pass
    raise RuntimeError('GitHub transport failed') from None


def installation_transport(jwt, installation_id, body):
    if type(installation_id) is not int or not 0 < installation_id < 2**63:
        raise RuntimeError('GitHub transport failed')
    return _request('POST', f'/app/installations/{installation_id}/access_tokens', jwt, body)


def read_transport(token, path):
    if (not isinstance(path, str) or not _PATH.fullmatch(path)
            or any(part in ('.', '..') for part in path.split('/'))):
        raise RuntimeError('GitHub transport failed')
    return _request('GET', path, token)


if __name__ == '__main__':
    sys.exit(_child())
