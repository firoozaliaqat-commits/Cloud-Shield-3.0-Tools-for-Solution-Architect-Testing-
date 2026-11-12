import http from 'k6/http';
import { check, sleep } from 'k6';
export const options = { thresholds: { checks: ['rate>0.99'] } };
const base = __ENV.BASE_URL || 'http://waf:8080';
export default function () {
  // A controlled SQLi-shaped string in an echo-only endpoint, never a real exploit.
  const payload = encodeURIComponent("1' OR '1'='1");
  const r = http.get(`${base}/target/echo?q=${payload}`);
  check(r, { 'Coraza WAF denied benign probe': x => x.status === 403 });
  sleep(0.6);
}
