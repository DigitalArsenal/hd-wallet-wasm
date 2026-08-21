import { describe, expect, test, vi } from 'vitest';

import {
  acquireMediaStreamForSession,
  readFileBytesForSession,
  stopMediaStream,
} from '../src/legacy-media-session.js';
import { SessionGenerationGuard } from '../src/session-generation.js';

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

describe('legacy media session ownership', () => {
  test('late file bytes are zeroed when logout invalidates their session', async () => {
    const guard = new SessionGenerationGuard();
    const sessionGeneration = guard.begin();
    const read = deferred();
    const buffer = new Uint8Array([1, 2, 3, 4, 5, 6]).buffer;
    const pending = readFileBytesForSession({
      arrayBuffer: () => read.promise,
      size: buffer.byteLength,
    }, {
      isCurrent: (generation) => guard.isCurrent(generation),
      sessionGeneration,
    });

    guard.invalidate();
    read.resolve(buffer);

    await expect(pending).resolves.toBeNull();
    expect([...new Uint8Array(buffer)]).toEqual([0, 0, 0, 0, 0, 0]);
  });

  test.each([
    ['missing', undefined],
    ['non-finite', Number.POSITIVE_INFINITY],
    ['negative', -1],
    ['fractional', 1.5],
    ['oversized', (2 * 1024 * 1024) + 1],
  ])('rejects a %s photo size before arrayBuffer is called', async (_label, size) => {
    const arrayBuffer = vi.fn(() => Promise.resolve(new ArrayBuffer(0)));
    await expect(readFileBytesForSession({ arrayBuffer, size }, {
      isCurrent: () => true,
      sessionGeneration: 1,
    })).rejects.toThrow(/file size/iu);
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  test('rejects and wipes a post-read byte length that differs from the declared size', async () => {
    const buffer = new Uint8Array([1, 2, 3, 4]).buffer;
    await expect(readFileBytesForSession({
      arrayBuffer: () => Promise.resolve(buffer),
      size: 3,
    }, {
      isCurrent: () => true,
      sessionGeneration: 1,
    })).rejects.toThrow(/file size/iu);
    expect([...new Uint8Array(buffer)]).toEqual([0, 0, 0, 0]);
  });

  test('a late getUserMedia result stops every track and is never returned', async () => {
    const guard = new SessionGenerationGuard();
    const sessionGeneration = guard.begin();
    const media = deferred();
    const tracks = [{ stop: vi.fn() }, { stop: vi.fn() }];
    const stream = { getTracks: () => tracks };
    const pending = acquireMediaStreamForSession({
      getUserMedia: () => media.promise,
    }, { video: true }, {
      isCurrent: (generation) => guard.isCurrent(generation),
      sessionGeneration,
    });

    guard.invalidate();
    media.resolve(stream);

    await expect(pending).resolves.toBeNull();
    expect(tracks.every((track) => track.stop.mock.calls.length === 1)).toBe(true);
  });

  test('stopping a current stream is synchronous and best effort for every track', () => {
    const tracks = [
      { stop: vi.fn(() => { throw new Error('first track failed'); }) },
      { stop: vi.fn() },
    ];
    stopMediaStream({ getTracks: () => tracks });
    expect(tracks.every((track) => track.stop.mock.calls.length === 1)).toBe(true);
  });

  test.each([
    ['missing', undefined],
    ['non-finite', Number.NaN],
    ['negative', -1],
    ['oversized', 5],
  ])('bounded text import rejects a %s size before constructing FileReader', async (_label, size) => {
    const media = await import('../src/legacy-media-session.js');
    expect(typeof media.readTextFileForSession).toBe('function');
    const FileReader = vi.fn();
    await expect(media.readTextFileForSession({ size }, {
      FileReader,
      isCurrent: () => true,
      maximumBytes: 4,
      sessionGeneration: 1,
    })).rejects.toThrow(/file size/iu);
    expect(FileReader).not.toHaveBeenCalled();
  });

  test('aborting a bounded text import aborts its retained reader and stale onload cannot settle it', async () => {
    const media = await import('../src/legacy-media-session.js');
    expect(typeof media.readTextFileForSession).toBe('function');
    const readers = [];
    class DeferredFileReader {
      constructor() {
        this.abort = vi.fn();
        this.readAsText = vi.fn();
        readers.push(this);
      }
    }
    const abort = new AbortController();
    const pending = media.readTextFileForSession({ size: 4 }, {
      FileReader: DeferredFileReader,
      isCurrent: () => true,
      maximumBytes: 4,
      sessionGeneration: 1,
      signal: abort.signal,
    });
    expect(readers).toHaveLength(1);
    const staleOnload = readers[0].onload;
    abort.abort();
    expect(readers[0].abort).toHaveBeenCalledTimes(1);
    readers[0].result = 'late';
    staleOnload();
    await expect(pending).rejects.toMatchObject({ code: 'STALE_SESSION' });
  });
});
