"""Fail-closed repository ID/name policy loaded from a local JSON file."""
import json
import re
from pathlib import Path

NAME = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')


def allowed(config):
    if isinstance(config, (str, Path)):
        with open(config, encoding='utf-8') as stream:
            document = json.load(stream)
        if not isinstance(document, dict) or set(document) != {'repositories'} or not isinstance(document['repositories'], list):
            raise ValueError('invalid repository configuration')
        entries = document['repositories']
    elif isinstance(config, dict):
        entries = [{'id': k, 'full_name': v, 'enabled': True} for k, v in config.items()]
    else:
        raise ValueError('invalid repository configuration')
    result, ids, names = {}, set(), set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'id', 'full_name', 'enabled'}:
            raise ValueError('invalid repository entry')
        ident, name, enabled = entry['id'], entry['full_name'], entry['enabled']
        if (type(ident) is not int or ident <= 0 or not isinstance(name, str)
                or not NAME.fullmatch(name) or any(part in ('.', '..') for part in name.split('/'))
                or type(enabled) is not bool or ident in ids or name.casefold() in names):
            raise ValueError('invalid or duplicate repository identity')
        ids.add(ident); names.add(name.casefold())
        if enabled:
            result[ident] = name
    return result
