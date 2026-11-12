import http from 'k6/http';
import { check, sleep } from 'k6';
const base = __ENV.BASE_URL || 'http://waf:8080';
export default function () {
  const r = http.get(`${base}/target/data`);
  check(r, { 'response 200 (or lab ban)': x => x.status === 200 || x.status === 429 });
  sleep(0.05);
}
