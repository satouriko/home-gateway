"""One stable, short-lived maintenance context; fresh detail bypasses this cache.

Monotonic TTL bounds volatile hardware/service sampling. Watched private-state
metadata invalidates immediately on writes/atomic replacement, rather than
waiting for the TTL. Errors never fall back to an earlier healthy snapshot.
"""
import copy
import itertools
import math
import os
from pathlib import Path
import threading
import time

TTL_SECONDS=60
MAX_PATHS=128
_lock=threading.RLock()
_entry=None
_generation=0


def _watch_set(paths):
    if isinstance(paths,(str,bytes,os.PathLike)):raise ValueError('a bounded collection of watch paths is required')
    selected=list(itertools.islice(paths,MAX_PATHS+1))
    if len(selected)>MAX_PATHS:raise ValueError('too many context watch paths')
    result=[]
    for path in selected:
        path=os.fspath(path)
        if not isinstance(path,str) or not path or len(path)>4096:raise ValueError('valid bounded context watch paths required')
        result.append(os.path.abspath(path))
    return tuple(sorted(set(result)))


def _metadata(paths):
    records=[]
    for path in paths:
        try:
            info=Path(path).stat()
            records.append((info.st_mtime_ns,info.st_ino,info.st_size))
        except FileNotFoundError:records.append(('missing',))
        except OSError:return None
    return tuple(records)


def invalidate():
    """Forget the one snapshot after a mutating operation (also safe in a factory)."""
    global _entry,_generation
    with _lock:
        _entry=None
        _generation+=1


def get(factory,paths,now=None):
    """Get an isolated context copy from a stable callable and watched file set.

    ``now`` is an optional monotonic reading, useful to callers owning a clock.
    The same stable callable object must be reused for hits; a new callable or
    watch set replaces the sole cache entry. Collection is serialized so two
    concurrent readers collect once. A mid-collection write/invalidation makes
    that result uncacheable; the next caller collects again. Missing paths are
    tracked, while other metadata errors force collection without caching.
    """
    global _entry
    if not callable(factory):raise ValueError('context factory must be callable')
    watched=_watch_set(paths)
    with _lock:
        instant=time.monotonic() if now is None else now
        if type(instant) not in (int,float) or not math.isfinite(instant) or instant<0:
            raise ValueError('valid monotonic cache time required')
        before=_metadata(watched)
        if (_entry is not None and _entry['factory'] is factory and _entry['paths']==watched
                and before is not None and before==_entry['metadata']
                and 0<=instant-_entry['at']<TTL_SECONDS):
            return copy.deepcopy(_entry['value'])
        _entry=None
        generation=_generation
        # Clear before running user code: collection/deepcopy errors propagate,
        # and neither an old context nor a partially collected one is retained.
        value=copy.deepcopy(factory())
        after=_metadata(watched)
        if before is not None and before==after and generation==_generation:
            _entry={'factory':factory,'paths':watched,'metadata':after,'at':instant,'value':value}
        return copy.deepcopy(value)
