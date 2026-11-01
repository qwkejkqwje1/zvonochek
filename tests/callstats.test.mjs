// Тесты чистого модуля статистики звонка: node --test tests/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  readCounters, deriveSample, mosOf, levelOf, mosLabel, CallRecorder, sparkPath,
  fmtDur, fmtDurWords, fmtDurShort, fmtKbps, plural, journalDigest, bridgeSample, ROUTE_LABELS, ROUTE_SHORT,
} from '../callstats.js';

const report = (list) => new Map(list.map((s) => [s.id, s]));

function chromeReport({ bytesIn = 0, packets = 0, lost = 0, bytesOut = 0, rtt = 0.05, relay = false } = {}) {
  return report([
    { id: 'T1', type: 'transport', selectedCandidatePairId: 'CP1' },
    { id: 'CP1', type: 'candidate-pair', localCandidateId: 'L1', remoteCandidateId: 'R1', currentRoundTripTime: rtt },
    { id: 'CP2', type: 'candidate-pair', localCandidateId: 'L2', remoteCandidateId: 'R1', currentRoundTripTime: 9 },
    { id: 'L1', type: 'local-candidate', candidateType: relay ? 'relay' : 'srflx', protocol: 'udp', relayProtocol: relay ? 'tls' : undefined },
    { id: 'L2', type: 'local-candidate', candidateType: 'host', protocol: 'udp' },
    { id: 'R1', type: 'remote-candidate', candidateType: 'srflx', protocol: 'udp' },
    { id: 'C1', type: 'codec', mimeType: 'audio/opus' },
    { id: 'IA', type: 'inbound-rtp', kind: 'audio', bytesReceived: bytesIn, packetsReceived: packets, packetsLost: lost, jitter: 0.012, codecId: 'C1' },
    { id: 'IV', type: 'inbound-rtp', kind: 'video', bytesReceived: 0, packetsReceived: 0, packetsLost: 0, frameWidth: 1280, frameHeight: 720, framesPerSecond: 29.6 },
    { id: 'OA', type: 'outbound-rtp', kind: 'audio', bytesSent: bytesOut },
    { id: 'RV', type: 'remote-inbound-rtp', kind: 'video', fractionLost: 0.03, roundTripTime: 0.06 },
  ]);
}

test('readCounters: выбранная пара через transport, маршрут, протокол, кодек', () => {
  const c = readCounters(chromeReport({ relay: true }), 1000);
  assert.equal(c.connected, true);
  assert.equal(c.route, 'turn');
  assert.equal(c.proto, 'UDP/TLS');
  assert.equal(c.rtt, 0.05);
  assert.equal(c.codec, 'opus');
  assert.deepEqual(c.videoIn, { w: 1280, h: 720, fps: 30 });
  assert.equal(c.remoteLoss.video, 3);
  const direct = readCounters(chromeReport(), 1000);
  assert.equal(direct.route, 'p2p');
  assert.equal(direct.proto, 'UDP');
});

test('readCounters: Firefox-стиль (selected на паре) и LAN', () => {
  const c = readCounters(report([
    { id: 'P', type: 'candidate-pair', selected: true, localCandidateId: 'L', remoteCandidateId: 'R' },
    { id: 'L', type: 'local-candidate', candidateType: 'host', protocol: 'udp' },
    { id: 'R', type: 'remote-candidate', candidateType: 'host', protocol: 'udp' },
  ]));
  assert.equal(c.route, 'lan');
  assert.equal(c.rtt, null);
});

test('readCounters: нет пары — не соединено', () => {
  const c = readCounters(report([{ id: 'x', type: 'codec' }]));
  assert.equal(c.connected, false);
  assert.equal(c.route, null);
});

test('deriveSample: потери и битрейт за интервал', () => {
  const a = readCounters(chromeReport({ bytesIn: 10000, packets: 100, lost: 0, bytesOut: 5000 }), 0);
  const b = readCounters(chromeReport({ bytesIn: 22500, packets: 195, lost: 5, bytesOut: 10000 }), 2000);
  const s = deriveSample(b, a);
  assert.equal(s.loss, 5); // 5 потеряно из 100 за интервал
  assert.equal(s.kbpsIn, 50); // 12500 байт * 8 / 2 с
  assert.equal(s.kbpsOut, 20);
  assert.equal(s.rtt, 50);
  assert.equal(s.jitter, 12);
  assert.equal(s.videoOutLoss, 3);
  assert.ok(s.mos > 3 && s.mos <= 4.5);
  assert.equal(s.level, 'mid');
  const first = deriveSample(a, null);
  assert.equal(first.loss, null);
  assert.equal(first.kbpsIn, null);
});

test('mosOf: монотонно падает с ухудшением сети', () => {
  const great = mosOf(40, 3, 0);
  const meh = mosOf(300, 30, 3);
  const awful = mosOf(900, 80, 25);
  assert.ok(great >= 4.3, `great=${great}`);
  assert.ok(meh < great && awful < meh, `${great} ${meh} ${awful}`);
  assert.ok(awful >= 1 && great <= 4.5);
  assert.equal(mosLabel(4.4).text, 'отлично');
  assert.equal(mosLabel(2).level, 'bad');
  assert.equal(mosLabel(null).text, 'нет данных');
});

test('levelOf: пороги индикатора', () => {
  assert.equal(levelOf({ rtt: 80, loss: 0.5 }), 'good');
  assert.equal(levelOf({ rtt: 300, loss: 1 }), 'mid');
  assert.equal(levelOf({ rtt: 600, loss: 1 }), 'bad');
  assert.equal(levelOf({ rtt: null, loss: null }), 'good');
});

test('CallRecorder: агрегаты, кольцевой буфер, основной маршрут', () => {
  const r = new CallRecorder({ capacity: 3, startedAt: 0 });
  r.push({ t: 0, route: 'p2p', rtt: 40, loss: 0, mos: 4.4, kbpsIn: 40 });
  r.push({ t: 2000, route: 'p2p', rtt: 60, loss: 2, mos: 4.2, kbpsIn: 60 });
  r.push({ t: 4000, route: 'turn', rtt: 140, loss: 1, mos: 4.0, kbpsIn: 50 });
  r.push(bridgeSample(6000));
  r.push({ t: 8000, route: 'turn', rtt: 100, loss: 1, mos: 4.1, kbpsIn: 50 });
  assert.equal(r.series('rtt').length, 3);
  assert.deepEqual(r.series('rtt'), [140, null, 100]);
  const s = r.summary(10000);
  assert.equal(s.dur, 10);
  assert.equal(s.rtt, 85);
  assert.equal(s.rttMax, 140);
  assert.equal(s.mosMin, 4);
  assert.equal(s.samples, 4);
  assert.equal(s.route, 'p2p'); // 4 с p2p, 2 с turn, 2 с bridge
  assert.equal(s.routeChanges, 3);
});

test('sparkPath: разрывы на null и пустые данные', () => {
  assert.deepEqual(sparkPath([]), { line: '', area: '' });
  const { line, area } = sparkPath([1, 2, null, 3, 4], 100, 20);
  assert.equal((line.match(/M/g) || []).length, 2);
  assert.equal((area.match(/Z/g) || []).length, 2);
  const flat = sparkPath([5, 5, 5], 100, 20, { min: 0, max: 10 });
  assert.match(flat.line, /^M2\.0,10\.0L50\.0,10\.0L98\.0,10\.0$/);
});

test('форматирование: длительность и битрейт', () => {
  assert.equal(fmtDur(65), '1:05');
  assert.equal(fmtDur(3723), '1:02:03');
  assert.equal(fmtDurWords(40), '40 с');
  assert.equal(fmtDurWords(7500), '2 ч 05 мин');
  assert.equal(fmtKbps(850), '850 Кбит/с');
  assert.equal(fmtKbps(1250), '1,3 Мбит/с');
  assert.equal(fmtKbps(null), '—');
  assert.equal(fmtDurShort(45), '45 с');
  assert.equal(fmtDurShort(720), '12 мин');
  assert.equal(fmtDurShort(7680), '2,1 ч');
  assert.equal(fmtDurShort(50400), '14 ч');
});

test('plural: русские формы для 1 / 2–4 / 5–20 / 11–14 / 21', () => {
  const p = (n) => plural(n, 'разговор', 'разговора', 'разговоров');
  assert.deepEqual([1, 2, 4, 5, 11, 12, 14, 21, 22, 25, 101, 111].map(p), [
    'разговор', 'разговора', 'разговора', 'разговоров', 'разговоров', 'разговоров',
    'разговоров', 'разговор', 'разговора', 'разговоров', 'разговор', 'разговоров',
  ]);
  assert.equal(p(0), 'разговоров');
});

test('у каждого маршрута есть полная и короткая подпись', () => {
  assert.deepEqual(Object.keys(ROUTE_SHORT).sort(), Object.keys(ROUTE_LABELS).sort());
});

test('journalDigest: KPI за 30 дней и дневной график', () => {
  const now = new Date(2026, 9, 31, 12, 0, 0).getTime();
  const day = 86400000;
  const entries = [
    { ts: now - 1000, outcome: 'completed', dur: 600, route: 'p2p', mos: 4.4, rtt: 40 },
    { ts: now - day, outcome: 'completed', dur: 300, route: 'turn', mos: 3.8, rtt: 160 },
    { ts: now - 2 * day, outcome: 'missed', dur: 0 },
    { ts: now - 40 * day, outcome: 'completed', dur: 999, route: 'p2p' },
  ];
  const d = journalDigest(entries, now);
  assert.equal(d.total, 3);
  assert.equal(d.talk, 2);
  assert.equal(d.missed, 1);
  assert.equal(d.talkSec, 900);
  assert.equal(d.avgRtt, 100);
  assert.equal(d.avgMos, 4.2); // взвешено по длительности
  assert.deepEqual(d.routes, { p2p: 1, lan: 0, turn: 1, bridge: 0 });
  assert.equal(d.perDay.length, 14);
  assert.equal(d.perDay[13].n, 1);
  assert.equal(d.perDay[12].sec, 300);
});
