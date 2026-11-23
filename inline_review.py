"""Conservative changed-line validation for model-generated review comments."""
import json
import re

PREFIX = 'pr-review-inline-v1:'
PATH = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*\Z')
HUNK = re.compile(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?\Z')


def changed_lines(diff):
    # ponytail: reject quoted/unusual paths and malformed sections rather than guessing.
    if not diff.endswith('\n'):
        return set()
    found = set()
    for section in re.split(r'^diff --git ', diff, flags=re.MULTILINE)[1:]:
        lines = section.splitlines()
        if not lines:
            continue
        match = re.fullmatch(r'a/([^ ]+) b/([^ ]+)', lines[0])
        if not match or match[1] != match[2] or not PATH.fullmatch(match[2]):
            continue
        path = match[2]
        try:
            i = lines.index('--- a/' + path)
        except ValueError:
            # New files have no old path.
            try:
                i = lines.index('--- /dev/null')
            except ValueError:
                continue
        if i + 1 >= len(lines) or lines[i + 1] != '+++ b/' + path:
            continue
        i += 2
        added = set()
        valid = True
        while i < len(lines):
            m = HUNK.fullmatch(lines[i])
            if not m:
                valid = False
                break
            old, new = int(m[2] or 1), int(m[4] or 1)
            line = int(m[3])
            i += 1
            while i < len(lines) and not lines[i].startswith('@@ '):
                s = lines[i]
                if s == r'\ No newline at end of file':
                    i += 1
                    continue
                if not s or s[0] not in ' +-':
                    valid = False
                    break
                if s[0] in ' -':
                    old -= 1
                if s[0] in ' +':
                    if s[0] == '+' and line > 0:
                        added.add((path, line))
                    line += 1
                    new -= 1
                if old < 0 or new < 0:
                    valid = False
                    break
                i += 1
            if not valid or old or new:
                valid = False
                break
        if valid:
            found.update(added)
    return found


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def prepare_review(text, diff):
    stripped = text.strip()
    if stripped.startswith('```'):
        fence = re.fullmatch(r'```(?:json)?[ \t]*\r?\n(.*?)\r?\n```', stripped, re.DOTALL | re.IGNORECASE)
        if fence and (stripped[3:7].lower() == 'json' or fence[1].lstrip().startswith(('{', '['))):
            text = fence[1]
        elif re.match(r'```json(?:\s|$)', stripped, re.IGNORECASE) or re.match(r'```[ \t]*\r?\n[ \t]*[\[{]', stripped):
            raise ValueError('invalid structured review')
    if not text.lstrip().startswith(('{', '[')):
        # ponytail: ambiguous structured fragments retry; ordinary code fences stay legacy text.
        if (PREFIX in text or re.search(r'```json(?:\s|$)|```[ \t]*\r?\n[ \t]*[\[{]|"(?:body|comments)"\s*:', text, re.IGNORECASE)):
            raise ValueError('invalid structured review')
        return text
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
        if (type(data) is not dict or set(data) != {'body', 'comments'} or
                not isinstance(data['body'], str) or type(data['comments']) is not list):
            raise ValueError()
        valid = changed_lines(diff)
        body = [data['body'].strip()]
        comments = []
        for item in data['comments']:
            if (type(item) is not dict or set(item) != {'path', 'line', 'body'} or
                    not isinstance(item['body'], str) or not item['body'].strip()):
                raise ValueError()
            path, line = item['path'], item['line']
            if isinstance(path, str) and type(line) is int and (path, line) in valid:
                comments.append({'path': path, 'line': line, 'side': 'RIGHT', 'body': item['body']})
            else:
                body.append(item['body'].strip())
        result = {'body': '\n\n'.join(s for s in body if s) or '리뷰 의견입니다.', 'comments': comments}
        return PREFIX + json.dumps(result, ensure_ascii=False, separators=(',', ':'))
    except (ValueError, TypeError, RecursionError):
        raise ValueError('invalid structured review') from None


def unpack_review(review):
    if not review.startswith(PREFIX):
        return review, []
    try:
        data = json.loads(review[len(PREFIX):], object_pairs_hook=_unique_object)
        if type(data) is not dict or set(data) != {'body', 'comments'} or not isinstance(data['body'], str) or not data['body'].strip() or type(data['comments']) is not list:
            raise ValueError()
        for item in data['comments']:
            if (type(item) is not dict or set(item) != {'path', 'line', 'side', 'body'} or
                    not isinstance(item['path'], str) or not PATH.fullmatch(item['path']) or
                    type(item['line']) is not int or item['line'] <= 0 or item['side'] != 'RIGHT' or
                    not isinstance(item['body'], str) or not item['body'].strip()):
                raise ValueError()
        return data['body'], data['comments']
    except (ValueError, TypeError, RecursionError):
        # ponytail: ambiguous legacy prefixes remain text and pass the publisher's secret check.
        return review, []
