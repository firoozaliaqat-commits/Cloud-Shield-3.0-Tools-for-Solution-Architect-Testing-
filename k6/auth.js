import http from 'k6/http';
import { check, sleep } from 'k6';
const base = __ENV.BASE_URL || 'http://waf:8080';
export default function () {
  const r = http.post(`${base}/target/login`, JSON.stringify({username:'student', password:'wrong-demo-password'}), {headers:{'Content-Type':'application/json'}});
  check(r, { 'auth denied by demo app or ban': x => x.status === 401 || x.status === 429 || x.status === 403 });
  sleep(0.25);
}
