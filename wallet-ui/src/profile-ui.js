/**
 * Profile: what people see when you share your contact card.
 *
 * View mode lists the non-empty fields; edit mode replaces it in place with
 * the inputs and the photo controls (upload, camera capture, remove). The
 * photo is re-encoded here to a 192×192 JPEG (quality 0.82, at most 32 KiB)
 * and kept in the profile as a data URL; it is displayed only through a
 * validated Blob URL (PhotoUrlController). The contact card download is a
 * signed $EPM built by ctx.contactCard (app.js + contact-card.js).
 */

import {
  actions,
  button,
  codeBlock,
  details,
  el,
  field,
  focusKey,
  input,
  muted,
  paneHead,
  requestFocus,
  row,
  setBusy,
  statusLine,
  swapPane,
} from './ui-dom.js';
import {
  MAX_OWN_PHOTO_BYTES,
  PROFILE_FIELDS,
  initialsOf,
  joinAddress,
  jpegDataUrl,
  normalizeProfile,
  photoBytesFromDataUrl,
} from './contact-card.js';
import { encryptionKeyPath, signingKeyPath, toHex } from './identity-keys.js';
import {
  acquireMediaStreamForSession,
  readFileBytesForSession,
  stopMediaStream,
  wipeSessionBytes,
} from './legacy-media-session.js';
import { PhotoUrlController, inspectPhotoBytes } from '../origin-app/photo.mjs';

export const PHOTO_SIZE = 192;
export const PHOTO_QUALITY = 0.82;
export const SEED_ONLY = 'Sign in with a seed phrase to use your SDN identity.';

const VIEW_ROWS = Object.freeze([
  ['name', 'Name'],
  ['jobTitle', 'Job title'],
  ['organization', 'Organization'],
  ['email', 'Email'],
  ['phone', 'Phone'],
]);

/** The view-mode rows for a profile: [label, value] pairs, empty ones left out. */
export function profileRows(profile) {
  const rows = [];
  for (const [id, label] of VIEW_ROWS) {
    const value = String(profile?.[id] ?? '').trim();
    if (value) rows.push([label, value]);
  }
  const address = joinAddress(profile ?? {});
  if (address) rows.push(['Address', address]);
  return rows;
}

/**
 * Draw `source` (an ImageBitmap, image or video) centre-cropped into a
 * 192×192 canvas and encode it as JPEG, stepping the quality down until it
 * fits in 32 KiB. Resolves to the JPEG bytes, or null when it cannot.
 */
export async function encodeSquareJpeg(doc, source, width, height) {
  if (!source || !width || !height) return null;
  const canvas = doc.createElement('canvas');
  canvas.width = PHOTO_SIZE;
  canvas.height = PHOTO_SIZE;
  const context = canvas.getContext?.('2d');
  if (!context) return null;
  const side = Math.min(width, height);
  const sx = Math.max(0, Math.round((width - side) / 2));
  const sy = Math.max(0, Math.round((height - side) / 2));
  context.imageSmoothingEnabled = true;
  context.imageSmoothingQuality = 'high';
  context.drawImage(source, sx, sy, side, side, 0, 0, PHOTO_SIZE, PHOTO_SIZE);
  for (const quality of [PHOTO_QUALITY, 0.7, 0.6]) {
    const blob = await new Promise((resolve) => {
      if (typeof canvas.toBlob === 'function') canvas.toBlob(resolve, 'image/jpeg', quality);
      else resolve(null);
    });
    if (!blob) return null;
    if (blob.size <= MAX_OWN_PHOTO_BYTES) return new Uint8Array(await blob.arrayBuffer());
  }
  return null;
}

/**
 * @param {HTMLElement} panel  #account-pane-profile
 * @param {object} ctx
 */
export function createProfilePane(panel, ctx) {
  const doc = panel.ownerDocument ?? ctx.document;
  let mode = 'view';
  let draft = null;
  let notice = null;
  let cameraStream = null;
  let generation = 0;
  const photoUrls = new PhotoUrlController();

  function stale(token) {
    return token !== generation || !ctx.isCurrent();
  }

  function stopCamera() {
    if (cameraStream) stopMediaStream(cameraStream);
    cameraStream = null;
  }

  function photoCircle(dataUrl, name, size) {
    const circle = el(doc, 'div', `photo-circle photo-${size}`);
    const bytes = dataUrl ? photoBytesFromDataUrl(dataUrl) : null;
    const initials = initialsOf(name);
    circle.append(el(doc, 'span', 'avatar-initials', initials));
    if (bytes) {
      const token = generation;
      photoUrls.replace(bytes).then((url) => {
        if (stale(token)) return;
        const image = el(doc, 'img');
        image.alt = '';
        image.src = url;
        image.onerror = () => { photoUrls.imageError(url); image.remove(); };
        circle.replaceChildren(image);
      }).catch(() => { /* initials stay */ });
    }
    return circle;
  }

  function renderView(wrap) {
    const profile = normalizeProfile(ctx.profile.get());
    const identity = ctx.session().identity;
    const account = ctx.session().account;
    const card = el(doc, 'div', 'profile-card');
    card.append(photoCircle(profile.photo, profile.name, 96));
    const rows = el(doc, 'div', 'rows profile-rows');
    const values = profileRows(profile);
    if (values.length === 0) rows.append(muted(doc, 'No details yet.'));
    for (const [label, value] of values) rows.append(row(doc, label, value));
    card.append(rows);
    wrap.append(card);

    const edit = focusKey(button(doc, 'Edit profile', { variant: 'primary' }), 'profile-edit');
    edit.addEventListener('click', () => startEdit());
    const download = button(doc, 'Download contact card');
    const result = el(doc, 'div', 'inline-result');
    download.addEventListener('click', async () => {
      const token = generation;
      setBusy(download, true, 'Preparing…');
      try {
        const { bytes, fileName } = await ctx.contactCard.build();
        if (stale(token)) return;
        ctx.download(bytes, fileName, 'application/octet-stream');
        result.replaceChildren(statusLine(doc, 'Saved', fileName));
      } catch (error) {
        if (stale(token)) return;
        result.replaceChildren(statusLine(doc, 'Not saved', error?.message || 'The contact card could not be built.', { error: true }));
      } finally {
        if (!stale(token)) setBusy(download, false);
      }
    });
    wrap.append(actions(doc, edit, download), result);
    if (notice) {
      // A notice stays on screen across re-renders; it is read out once.
      wrap.append(statusLine(doc, notice.word, notice.message, { error: Boolean(notice.error), speak: !notice.spoken }));
      notice.spoken = true;
    }

    wrap.append(details(doc, [
      codeBlock(doc, { label: 'Peer ID', value: identity?.peerId ?? '' }).block,
      codeBlock(doc, { label: `Ed25519 · ${signingKeyPath(account)}`, value: identity ? toHex(identity.edPub) : '' }).block,
      codeBlock(doc, { label: `X25519 · ${encryptionKeyPath(account)}`, value: identity ? toHex(identity.xPub) : '' }).block,
      muted(doc, 'Your contact card is a Space Data Standards $EPM record signed with your Ed25519 key.'),
    ]).node);
  }

  function startEdit() {
    draft = normalizeProfile(ctx.profile.get());
    mode = 'edit';
    notice = null;
    requestFocus(panel, 'profile-name');
    render();
  }

  async function installPhotoBytes(bytes, token, status) {
    // Validate the encoded bytes like any other photo before keeping them.
    try {
      inspectPhotoBytes(bytes);
    } catch {
      status.replaceChildren(statusLine(doc, 'Not added', 'This photo could not be read.', { error: true }));
      return;
    }
    if (stale(token)) return;
    draft.photo = jpegDataUrl(bytes);
    requestFocus(panel, 'photo-upload');
    render();
  }

  async function encodeFromFile(file, token, status) {
    let bytes = null;
    try {
      bytes = await readFileBytesForSession(file, {
        isCurrent: () => ctx.isCurrent(),
        sessionGeneration: true,
      });
      if (!bytes || stale(token)) return;
      const inspected = inspectPhotoBytes(bytes);
      const BlobCtor = doc.defaultView?.Blob ?? globalThis.Blob;
      const host = doc.defaultView ?? globalThis;
      if (typeof host.createImageBitmap !== 'function') throw new Error('decoder');
      const bitmap = await host.createImageBitmap(new BlobCtor([inspected.bytes], { type: inspected.type }));
      try {
        if (stale(token)) return;
        const jpeg = await (ctx.encodePhoto ?? encodeSquareJpeg)(doc, bitmap, bitmap.width, bitmap.height);
        if (stale(token)) return;
        if (!jpeg) {
          status.replaceChildren(statusLine(doc, 'Not added', 'This photo is too detailed to fit in a contact card.', { error: true }));
          return;
        }
        await installPhotoBytes(jpeg, token, status);
      } finally {
        try { bitmap.close?.(); } catch { /* released */ }
      }
    } catch {
      if (stale(token)) return;
      status.replaceChildren(statusLine(doc, 'Not added', 'Choose a PNG, JPEG, WebP or GIF image up to 2 MB.', { error: true }));
    } finally {
      wipeSessionBytes(bytes);
    }
  }

  function renderEdit(wrap) {
    const token = generation;
    const photoRow = el(doc, 'div', 'photo-edit');
    const status = el(doc, 'div', 'inline-result');
    photoRow.append(photoCircle(draft.photo, draft.name, 96));
    const controls = el(doc, 'div', 'photo-controls');
    const upload = focusKey(button(doc, 'Upload photo', { variant: 'link' }), 'photo-upload');
    const take = focusKey(button(doc, 'Take photo', { variant: 'link' }), 'photo-take');
    const remove = focusKey(button(doc, 'Remove photo', { variant: 'link' }), 'photo-remove');
    remove.hidden = !draft.photo;
    const fileInput = el(doc, 'input');
    fileInput.type = 'file';
    fileInput.accept = 'image/png,image/jpeg,image/webp,image/gif';
    fileInput.hidden = true;
    fileInput.addEventListener('change', () => {
      const file = fileInput.files && fileInput.files[0];
      fileInput.value = '';
      if (file) void encodeFromFile(file, token, status);
    });
    upload.addEventListener('click', () => fileInput.click());
    remove.addEventListener('click', () => {
      draft.photo = '';
      requestFocus(panel, 'photo-upload');
      render();
    });
    const media = doc.defaultView?.navigator?.mediaDevices ?? globalThis.navigator?.mediaDevices;
    take.hidden = typeof media?.getUserMedia !== 'function';
    controls.append(upload, take, remove, fileInput);
    photoRow.append(controls);

    const camera = el(doc, 'div', 'camera');
    camera.hidden = true;
    const video = el(doc, 'video', 'camera-video');
    video.autoplay = true;
    video.muted = true;
    video.playsInline = true;
    const capture = button(doc, 'Capture', { variant: 'primary', small: true });
    const cancelCamera = button(doc, 'Cancel', { small: true });
    camera.append(video, actions(doc, capture, cancelCamera));

    take.addEventListener('click', async () => {
      try {
        const stream = await acquireMediaStreamForSession(media, {
          video: { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } },
        }, { isCurrent: () => !stale(token), sessionGeneration: true });
        if (!stream) return;
        stopCamera();
        cameraStream = stream;
        video.srcObject = stream;
        camera.hidden = false;
        controls.hidden = true;
        capture.focus?.();
        await video.play?.();
      } catch {
        if (!stale(token)) status.replaceChildren(statusLine(doc, 'No camera', 'Could not open the camera. Check the browser permission.', { error: true }));
      }
    });
    cancelCamera.addEventListener('click', () => {
      stopCamera();
      video.srcObject = null;
      camera.hidden = true;
      controls.hidden = false;
      take.focus?.();
    });
    capture.addEventListener('click', async () => {
      const jpeg = await (ctx.encodePhoto ?? encodeSquareJpeg)(doc, video, video.videoWidth, video.videoHeight);
      stopCamera();
      video.srcObject = null;
      if (stale(token)) return;
      if (!jpeg) {
        camera.hidden = true;
        controls.hidden = false;
        status.replaceChildren(statusLine(doc, 'Not added', 'The camera produced no usable image.', { error: true }));
        return;
      }
      await installPhotoBytes(jpeg, token, status);
    });

    wrap.append(photoRow, camera, status);
    const form = el(doc, 'div', 'profile-form');
    for (const spec of PROFILE_FIELDS) {
      const control = input(doc, { type: spec.type ?? 'text', value: draft[spec.id] ?? '', autocomplete: 'off' });
      focusKey(control, `profile-${spec.id}`);
      control.addEventListener('input', () => { draft[spec.id] = control.value; });
      form.append(field(doc, spec.label, control));
    }
    wrap.append(form);
    const save = button(doc, 'Save', { variant: 'primary' });
    const cancel = button(doc, 'Cancel');
    save.addEventListener('click', () => {
      stopCamera();
      ctx.profile.save(normalizeProfile(draft));
      draft = null;
      mode = 'view';
      notice = null;
      requestFocus(panel, 'profile-edit');
      render();
    });
    cancel.addEventListener('click', () => {
      stopCamera();
      draft = null;
      mode = 'view';
      requestFocus(panel, 'profile-edit');
      render();
    });
    wrap.append(actions(doc, save, cancel));
  }

  function render() {
    generation += 1;
    const profile = normalizeProfile(ctx.profile.get());
    const wrap = el(doc, 'div', 'pane');
    const { head } = paneHead(doc, {
      eyebrow: 'Profile',
      title: profile.name || 'Your profile',
      lede: 'This is what people see when you share your contact card.',
    });
    wrap.append(head);
    if (ctx.session().kind !== 'seed' || !ctx.session().identity) {
      wrap.append(muted(doc, SEED_ONLY));
    } else if (mode === 'edit' && draft) {
      renderEdit(wrap);
    } else {
      renderView(wrap);
    }
    swapPane(panel, wrap);
  }

  return Object.freeze({
    render,
    show(intent) {
      if (intent?.edit && ctx.session().kind === 'seed') {
        startEdit();
        return;
      }
      render();
    },
    reset() {
      generation += 1;
      stopCamera();
      mode = 'view';
      draft = null;
      notice = null;
      photoUrls.logout();
      panel.replaceChildren();
    },
    destroy() {
      stopCamera();
      photoUrls.destroy();
    },
    get mode() { return mode; },
  });
}
