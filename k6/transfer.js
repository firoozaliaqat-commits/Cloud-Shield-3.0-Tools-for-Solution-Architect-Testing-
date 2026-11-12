import http from 'k6/http';
import { check, sleep } from 'k6';
const base = __ENV.BASE_URL || 'http://waf:8080';
export default function () {
  const r = http.get(`${base}/target/download?mb=4`, { responseType: 'none', timeout: '30s' });
  check(r, { '4 MiB download succeeded': x => x.status === 200 });
  sleep(0.6);
}
