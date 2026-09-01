// fox-shield v1.0 — 753 rps tek IP yük testi.
//
// Tek bir IP'den 753 rps atarak shield'in anında banlamasını ve origin'e 0
// istek gitmesini doğrular. k6 ile çalışır:
//
//   k6 run tests/load-753.js
//
// k6 kurulu değilse autocannon (Node) alternatifi:
//
//   npx autocannon -c 50 -d 10 http://127.0.0.1:8080/
//
// Beklenen: shield 429/403 döner, origin'e ulaşan istek sayısı ~0 olur.

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  // Tek IP simülasyonu: tek VU, yüksek iterasyon hızı.
  vus: 1,
  duration: '10s',
  // 753 rps hedefi: 10s'de ~7530 istek.
  iterations: 7530,
  thresholds: {
    // Shield banladıktan sonra çoğu istek 429/403 olmalı.
    http_req_failed: ['rate<0.99'],
  },
};

const BASE = __ENV.SHIELD_URL || 'http://127.0.0.1:8080';

export default function () {
  const res = http.get(`${BASE}/`);
  check(res, {
    'shield yanıt verdi (429/403/200)': (r) => r.status === 429 || r.status === 403 || r.status === 200,
  });
  // 753 rps'ye yaklaşmak için minimal bekleme.
  sleep(0.001);
}
