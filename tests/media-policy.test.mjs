// v37: медиа-политика — класс устройства, ступени захвата, подсказка
// собеседнику, параметры кодера и порядок кодеков. Ошибка здесь = либо
// перегретый телефон, либо мыло вместо видео на компьютере.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  VTIERS,
  VQ_CHOICES,
  deviceClass,
  autoTierId,
  captureTier,
  tierConstraints,
  rxCap,
  parseCap,
  QLEVELS,
  bpsForHeight,
  videoEncoding,
  preferCodecs,
  audioCodecOrder,
  videoCodecOrder,
} from '../media-policy.js';

test('класс устройства: ПК, телефон, слабый телефон, iPhone', () => {
  assert.equal(deviceClass({ mem: 8, cores: 8, mobile: false }), 'high');
  assert.equal(deviceClass({ mem: 2, cores: 4, mobile: false }), 'mid');
  assert.equal(deviceClass({ mem: 4, cores: 8, mobile: true }), 'mid');
  assert.equal(deviceClass({ mem: 2, cores: 8, mobile: true }), 'low'); // «4 ГБ» телефон сообщает 2
  assert.equal(deviceClass({ mem: 0, cores: 4, mobile: true }), 'low');
  assert.equal(deviceClass({ ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)', mobile: true }), 'mid');
  assert.equal(deviceClass({}), 'high'); // нет данных о ПК — не режем качество
});

test('«Авто»: ПК 1080p@30, телефон 720p@30, слабый 480p@24', () => {
  assert.equal(autoTierId('high'), '1080');
  const hi = captureTier('auto', 'high');
  assert.deepEqual([hi.w, hi.h, hi.fps, hi.manual], [1920, 1080, 30, false]);
  const mid = captureTier('auto', 'mid');
  assert.deepEqual([mid.h, mid.fps], [720, 30]);
  const low = captureTier('auto', 'low');
  assert.deepEqual([low.w, low.h, low.fps], [854, 480, 24]);
  assert.ok(VQ_CHOICES.includes('auto') && VQ_CHOICES.includes('480'));
});

test('ручной выбор — потолок; эко не выше 720p@24 (как в v34)', () => {
  assert.equal(captureTier('1440', 'low').h, 1440);
  assert.equal(captureTier('1440', 'low').manual, true);
  const eco = captureTier('1080', 'high', { eco: true });
  assert.deepEqual([eco.h, eco.fps], [720, 24]);
  const ecoLow = captureTier('auto', 'low', { eco: true });
  assert.deepEqual([ecoLow.h, ecoLow.fps], [360, 20]);
  assert.deepEqual(captureTier('nonsense', 'mid').h, 720); // мусор из localStorage = «Авто»
});

test('нагрузка снижает ступень; заряд — только в «Авто»; ниже 360p не падаем', () => {
  assert.equal(captureTier('auto', 'high', { cpu: 1 }).h, 720);
  assert.equal(captureTier('auto', 'high', { cpu: 1, pressure: 1 }).h, 480);
  assert.equal(captureTier('auto', 'mid', { battLow: true }).h, 480);
  assert.equal(captureTier('720', 'mid', { battLow: true }).h, 720);
  assert.equal(captureTier('1080', 'high', { cpu: 3, pressure: 2 }).h, 360);
  assert.deepEqual(captureTier('auto', 'mid', { cpu: 1 }).why, ['нагрузка ЦП']);
  assert.deepEqual(tierConstraints(VTIERS[2]), { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30, max: 30 } });
});

test('подсказка приёма: скрытый экран = 0, слабому — до 720p, нагрузка снижает', () => {
  assert.deepEqual(rxCap('high'), { h: 1440, fps: 30 });
  assert.deepEqual(rxCap('mid'), { h: 1080, fps: 30 });
  assert.deepEqual(rxCap('low'), { h: 720, fps: 30 });
  assert.deepEqual(rxCap('low', { cpu: 1 }), { h: 480, fps: 24 });
  assert.deepEqual(rxCap('mid', { cpu: 3, pressure: 2 }), { h: 360, fps: 20 });
  assert.deepEqual(rxCap('high', { eco: true }), { h: 720, fps: 30 });
  assert.deepEqual(rxCap('high', { hidden: true }), { h: 0, fps: 0 });
});

test('подсказка от собеседника проверяется: мусор отбрасывается', () => {
  assert.deepEqual(parseCap({ h: 720, fps: 24 }), { h: 720, fps: 24 });
  assert.deepEqual(parseCap({ h: 0, fps: 0 }), { h: 0, fps: 0 });
  assert.deepEqual(parseCap({ h: 480, fps: 999 }), { h: 480, fps: 60 });
  assert.equal(parseCap({ h: -1 }), null);
  assert.equal(parseCap({ h: 'x' }), null);
  assert.equal(parseCap({ h: 99999 }), null);
  assert.equal(parseCap(null), null);
});

test('кодер при захвате 1080p совпадает с лестницей v34–v36', () => {
  const src = { w: 1920, h: 1080 };
  const exp = [
    [1, 30, 2500000],
    [1.5, 30, 1200000],
    [2, 24, 600000],
    [3, 15, 250000],
    [4, 10, 120000],
  ];
  QLEVELS.forEach((_, i) => {
    const e = videoEncoding(i, src, null);
    assert.deepEqual([e.scaleResolutionDownBy, e.maxFramerate, e.maxBitrate, e.active], [...exp[i], true], 'уровень ' + i);
  });
  assert.equal(videoEncoding(0, { w: 2560, h: 1440 }, null).maxBitrate, 5500000); // 2K — решение владельца
  assert.equal(videoEncoding(0, src, null, { eco: true }).scaleResolutionDownBy, 1.5); // эко: не выше ступени 1
});

test('кодер учитывает собеседника и портретный кадр; h=0 выключает видео', () => {
  const e = videoEncoding(0, { w: 1920, h: 1080 }, { h: 720, fps: 24 });
  assert.deepEqual([e.scaleResolutionDownBy, e.maxFramerate, e.maxBitrate, e.h], [1.5, 24, 1500000, 720]);
  const portrait = videoEncoding(0, { w: 720, h: 1280 }, null);
  assert.deepEqual([portrait.scaleResolutionDownBy, portrait.h, portrait.maxBitrate], [1, 720, 1500000]);
  const low = videoEncoding(0, { w: 854, h: 480 }, null, { srcFps: 24 });
  assert.deepEqual([low.scaleResolutionDownBy, low.maxFramerate, low.maxBitrate], [1, 24, 900000]);
  assert.equal(videoEncoding(0, { w: 1280, h: 720 }, { h: 0, fps: 0 }).active, false);
  assert.equal(videoEncoding(2, {}, null).h, 540); // нет настроек трека — считаем 720p
  assert.equal(bpsForHeight(270), 200000);
});

const AUDIO = [
  { mimeType: 'audio/opus', clockRate: 48000, channels: 2 },
  { mimeType: 'audio/red', clockRate: 48000, channels: 2 },
  { mimeType: 'audio/G722', clockRate: 8000 },
];
const VIDEO = [
  { mimeType: 'video/VP8' },
  { mimeType: 'video/rtx', sdpFmtpLine: 'apt=96' },
  { mimeType: 'video/H264', sdpFmtpLine: 'level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f' },
  { mimeType: 'video/H264', sdpFmtpLine: 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f' },
  { mimeType: 'video/H264', sdpFmtpLine: 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f' },
  { mimeType: 'video/AV1' },
];

test('RED первым, Opus остаётся; без RED или выключено — ничего не меняем', () => {
  assert.deepEqual(audioCodecOrder(AUDIO).map((c) => c.mimeType), ['audio/red', 'audio/opus', 'audio/G722']);
  assert.equal(audioCodecOrder(AUDIO, false), null);
  assert.equal(audioCodecOrder(AUDIO.filter((c) => c.mimeType !== 'audio/red')), null);
  assert.equal(audioCodecOrder([{ mimeType: 'audio/red' }]), null); // RED без Opus бессмыслен
});

test('H.264 первым только по запросу; внутри — pm=1 + Constrained Baseline', () => {
  assert.equal(videoCodecOrder(VIDEO, false), null);
  assert.equal(videoCodecOrder(VIDEO.filter((c) => c.mimeType !== 'video/H264'), true), null);
  const o = videoCodecOrder(VIDEO, true).map((c) => c.mimeType + ' ' + (c.sdpFmtpLine || ''));
  assert.match(o[0], /H264 .*packetization-mode=1;profile-level-id=42e01f/);
  assert.match(o[1], /H264 .*packetization-mode=1;profile-level-id=640c1f/);
  assert.match(o[2], /H264 .*packetization-mode=0/);
  assert.deepEqual(o.slice(3).map((x) => x.split(' ')[0]), ['video/VP8', 'video/rtx', 'video/AV1']); // rtx сохранён
  assert.deepEqual(preferCodecs([1, 2, 3, 4], (x) => x % 2 === 0), [2, 4, 1, 3]);
});

test('SDP: первый кодек секции — RED виден из answer, даже если getStats пишет Opus', async () => {
  const { sdpFirstCodec } = await import('../media-policy.js');
  const sdp = [
    'v=0',
    'm=audio 9 UDP/TLS/RTP/SAVPF 63 111',
    'a=rtpmap:111 opus/48000/2',
    'a=rtpmap:63 red/48000/2',
    'm=video 9 UDP/TLS/RTP/SAVPF 102 96',
    'a=rtpmap:96 VP8/90000',
    'a=rtpmap:102 H264/90000',
  ].join('\r\n');
  assert.equal(sdpFirstCodec(sdp, 'audio'), 'red');
  assert.equal(sdpFirstCodec(sdp, 'video'), 'h264');
  assert.equal(sdpFirstCodec('v=0\r\nm=audio 9 X 111\r\na=rtpmap:111 opus/48000/2', 'audio'), 'opus');
  assert.equal(sdpFirstCodec('', 'audio'), '');
});

// v41: эхоподавление «Авто» — наушники/гарнитура → выкл, динамик и всё
// неизвестное → вкл. Ошибка в сторону «вкл» безопасна (собеседник не
// слышит эхо), в сторону «выкл» — нет, поэтому сомнительное = динамик.
test('AEC «Авто»: тип выхода по названиям устройств', async () => {
  const { audioRoute, routeOfLabel, echoWanted } = await import('../media-policy.js');
  const dev = (kind, label, deviceId = label) => ({ kind, label, deviceId });
  // Windows / macOS, англ. и рус.
  assert.equal(routeOfLabel('Default - Headphones (Realtek(R) Audio)'), 'headset');
  assert.equal(routeOfLabel('По умолчанию - Наушники (Realtek(R) Audio)'), 'headset');
  assert.equal(routeOfLabel('Головной телефон (WH-1000XM4 Hands-Free AG Audio)'), 'headset');
  assert.equal(routeOfLabel('Galaxy Buds2 Pro'), 'headset');
  assert.equal(routeOfLabel('AirPods Pro — Иван'), 'headset');
  assert.equal(routeOfLabel('Headset Earphone (HyperX Cloud II)'), 'headset');
  assert.equal(routeOfLabel('Default - Speakers (Realtek(R) Audio)'), 'speaker');
  assert.equal(routeOfLabel('Динамики MacBook Pro'), 'speaker');
  assert.equal(routeOfLabel('Speakers/Headphones (Realtek(R) Audio)'), 'speaker'); // общий разъём — осторожно
  assert.equal(routeOfLabel('Echo Cancelling Speakerphone (Jabra SPEAK 510)'), 'speaker');
  assert.equal(routeOfLabel('LG TV (NVIDIA High Definition Audio)'), 'unknown');
  assert.equal(routeOfLabel(''), 'unknown');

  // Компьютер: решает выход по умолчанию, затем выбранный динамик.
  const pc = [
    dev('audioinput', 'Default - Microphone (Realtek(R) Audio)', 'default'),
    dev('audiooutput', 'Default - Headphones (Realtek(R) Audio)', 'default'),
    dev('audiooutput', 'Speakers (USB Audio)', 'spk2'),
  ];
  assert.equal(audioRoute(pc), 'headset');
  assert.equal(audioRoute(pc, { spkId: 'spk2' }), 'speaker');
  // Выход не узнан (HDMI, Linux «Built-in Audio») — по микрофону гарнитуры.
  const hdmi = [dev('audioinput', 'Headset Microphone (Jabra Evolve 65)', 'default'), dev('audiooutput', 'Built-in Audio Analog Stereo', 'default')];
  assert.equal(audioRoute(hdmi), 'headset');
  assert.equal(audioRoute([dev('audioinput', 'Built-in Audio Analog Stereo', 'default')]), 'unknown');
  // Метки ещё скрыты (до разрешения на микрофон) — неизвестно.
  assert.equal(audioRoute([dev('audioinput', '', 'default'), dev('audiooutput', '', 'default')]), 'unknown');

  // Android Chrome: «Headset earpiece» — разговорный динамик, а не гарнитура.
  const phone = [dev('audioinput', 'Default', 'default'), dev('audioinput', 'Speakerphone'), dev('audioinput', 'Headset earpiece')];
  assert.equal(audioRoute(phone), 'speaker');
  assert.equal(audioRoute([...phone, dev('audioinput', 'Wired headset')]), 'headset');
  assert.equal(audioRoute([...phone, dev('audioinput', 'Bluetooth headset')]), 'headset');
  assert.equal(audioRoute([...phone, dev('audioinput', 'Bluetooth headset')], { micId: 'Speakerphone' }), 'speaker');
  // iPhone: только микрофоны, решает название трека.
  assert.equal(audioRoute([dev('audioinput', 'iPhone Microphone')], { micLabel: 'AirPods Pro' }), 'headset');
  assert.equal(audioRoute([dev('audioinput', 'iPhone Microphone')]), 'unknown');

  assert.equal(echoWanted('auto', 'headset'), false);
  assert.equal(echoWanted('auto', 'speaker'), true);
  assert.equal(echoWanted('auto', 'unknown'), true);
  assert.equal(echoWanted('on', 'headset'), true);
  assert.equal(echoWanted('off', 'speaker'), false);
});
