"""Bounded-memory JSONL audit paging with a private incremental offset index.

Only complete, valid JSON object lines are visible. Snapshots survive appends and
expire when the source is rotated, truncated, or its indexed boundary changes.
The disposable index lives next to the supplied runtime log; no HOME lookup occurs.
"""
from contextlib import closing
import hashlib
import json
import os
import sqlite3
import stat
import uuid

MAX_LINE_BYTES = 256 * 1024
_ANCHOR_BYTES = 4096


def _digest(fh, offset, length):
    fh.seek(offset)
    return hashlib.sha256(fh.read(length)).hexdigest()


def _index_connection(path):
    # O_NOFOLLOW protects an already-existing symlink; the inode check also
    # rejects special files and catches a replacement during sqlite's open.
    index_path = os.fspath(path) + '.index.sqlite3'
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(index_path, flags, 0o600)
    try:
        expected = os.fstat(fd)
        if not stat.S_ISREG(expected.st_mode):
            raise ValueError('audit index must be a regular file')
        os.fchmod(fd, 0o600)
        conn = sqlite3.connect(index_path, timeout=15)
        actual = os.stat(index_path, follow_symlinks=False)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            conn.close()
            raise ValueError('audit index changed while opening')
    finally:
        os.close(fd)
    conn.execute('PRAGMA journal_mode=DELETE')
    conn.execute('PRAGMA cache_size=-2048')
    conn.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS entries (offset INTEGER PRIMARY KEY, length INTEGER NOT NULL, tool TEXT, actor TEXT, decision TEXT, alias TEXT)')
    conn.commit()
    return conn


def _refresh(conn, fh):
    info = os.fstat(fh.fileno())
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('audit log must be a regular file')
    row = conn.execute('SELECT value FROM state WHERE id=1').fetchone()
    state = json.loads(row[0]) if row else None
    valid = (state and state['dev'] == info.st_dev and state['ino'] == info.st_ino
             and info.st_size >= state['end']
             and _digest(fh, 0, state['prefix_len']) == state['prefix']
             and _digest(fh, state['anchor_start'], state['end'] - state['anchor_start']) == state['anchor'])
    if not valid:
        conn.execute('DELETE FROM entries')
        state = {'generation': uuid.uuid4().hex, 'dev': info.st_dev, 'ino': info.st_ino, 'end': 0}
    fh.seek(state['end'])
    # Pin the visible length for this refresh, even while another process appends.
    ceiling = info.st_size
    while fh.tell() < ceiling:
        offset = fh.tell()
        raw = fh.readline(min(MAX_LINE_BYTES + 1, ceiling - offset))
        oversized = len(raw) > MAX_LINE_BYTES
        if oversized and not raw.endswith(b'\n'):
            while fh.tell() < ceiling:
                chunk = fh.readline(min(MAX_LINE_BYTES + 1, ceiling - fh.tell()))
                if chunk.endswith(b'\n'):
                    raw = chunk
                    break
                raw = chunk
        if not raw.endswith(b'\n'):
            # Leave incomplete bytes uncommitted for the next call.
            break
        end = fh.tell()
        state['end'] = end
        if oversized:
            continue
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            continue
        if not isinstance(record, dict):
            continue
        fields = [record.get(key) if isinstance(record.get(key), str) else None
                  for key in ('tool', 'actor', 'decision', 'alias')]
        conn.execute('INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?,?)',
                     (offset, end - offset, *fields))
    state['prefix_len'] = min(_ANCHOR_BYTES, state['end'])
    state['prefix'] = _digest(fh, 0, state['prefix_len'])
    state['anchor_start'] = max(0, state['end'] - _ANCHOR_BYTES)
    state['anchor'] = _digest(fh, state['anchor_start'], state['end'] - state['anchor_start'])
    conn.execute('INSERT OR REPLACE INTO state VALUES (1,?)', (json.dumps(state),))
    return state


def read_audit_page(path, tool='all', page=1, page_size=50, actor=None,
                    decision=None, alias=None, snapshot=None):
    """Return newest-first audit records and count after applying exact filters.

    Raises ValueError on invalid parameters or an expired/invalid snapshot.
    page is one-based; an out-of-range page is an empty page. Empty logs have
    zero pages. Index writes are serialized with SQLite's transaction lock.
    """
    if type(page) is not int or page < 1 or type(page_size) is not int or not 1 <= page_size <= 200:
        raise ValueError('page must be >=1 and page_size must be 1..200')
    if tool not in ('all', 'ssh', 'db', None):
        raise ValueError('invalid audit tool')
    for value in (actor, decision, alias):
        if value is not None and (not isinstance(value, str) or len(value) > 512):
            raise ValueError('invalid audit filter')
    if snapshot is not None and (not isinstance(snapshot, str) or len(snapshot) > 100):
        raise ValueError('invalid audit snapshot')
    result = {'entries': [], 'total': 0, 'page': page, 'page_size': page_size,
              'pages': 0, 'has_next': False, 'has_prev': False, 'snapshot': None}
    try:
        fh = open(path, 'rb')
    except FileNotFoundError:
        if snapshot is not None:
            raise ValueError('audit snapshot expired; reload the first page') from None
        return result
    with fh, closing(_index_connection(path)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        state = _refresh(conn, fh)
        cutoff = state['end']
        if snapshot is not None:
            try:
                generation, text = snapshot.split(':')
                requested = int(text)
                if generation != state['generation'] or requested < 0 or requested > cutoff:
                    raise ValueError()
                cutoff = requested
            except (ValueError, TypeError):
                raise ValueError('audit snapshot expired or invalid; reload the first page') from None
        token = '%s:%d' % (state['generation'], cutoff)
        clauses, values = ['offset < ?'], [cutoff]
        for key, value in (('tool', tool if tool not in ('all', None) else None),
                           ('actor', actor), ('decision', decision), ('alias', alias)):
            if value is not None:
                clauses.append(key + ' = ?')
                values.append(value)
        where = ' AND '.join(clauses)
        total = conn.execute('SELECT count(*) FROM entries WHERE ' + where, values).fetchone()[0]
        entries = []
        if (page - 1) * page_size < total:
            rows = conn.execute('SELECT offset,length FROM entries WHERE ' + where
                                + ' ORDER BY offset DESC LIMIT ? OFFSET ?',
                                values + [page_size, (page - 1) * page_size])
            for offset, length in rows:
                fh.seek(offset)
                try:
                    record = json.loads(fh.read(length))
                except (ValueError, UnicodeError):
                    raise ValueError('audit log changed during paging; reload') from None
                if not isinstance(record, dict):
                    raise ValueError('audit log changed during paging; reload')
                entries.append(record)
        pages = (total + page_size - 1) // page_size
        result.update(entries=entries, total=total, pages=pages,
                      has_next=page < pages, has_prev=page > 1 and total > 0, snapshot=token)
    return result
