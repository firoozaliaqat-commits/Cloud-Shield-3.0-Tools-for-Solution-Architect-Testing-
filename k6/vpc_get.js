import http from 'k6/http';
import { check, sleep } from 'k6';
// Approved path/URL supplied ONLY by an instructor's ECS environment, never from UI input.
const url = __ENV.BASE_URL;
export default function () {
  const response = http.get(url, { timeout: '10s', redirects: 0 });
  check(response, { 'private VPC HTTP target responded': r => r.status >= 200 && r.status < 400 });
  sleep(0.4);
}
