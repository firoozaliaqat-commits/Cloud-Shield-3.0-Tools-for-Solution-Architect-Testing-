import http from 'k6/http';
import { check, sleep } from 'k6';
const base = __ENV.BASE_URL || 'http://waf:8080';
export default function () {
  const a = http.get(`${base}/target/health`);
  const b = http.get(`${base}/target/data`);
  const c = http.post(`${base}/target/login`, JSON.stringify({username:'student', password:'classroom-demo'}), {headers:{'Content-Type':'application/json'}});
  check(a,{ 'health 200': r => r.status === 200 });
  check(b,{ 'sample data 200': r => r.status === 200 });
  check(c,{ 'demo login 200': r => r.status === 200 });
  sleep(0.45);
}
