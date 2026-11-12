import http from 'k6/http';
import { check, sleep } from 'k6';
// Realistic, bounded storefront user journey against the protected internal app.
// No payments, no real customer data, no external requests.
const base = __ENV.BASE_URL || 'http://waf:8080';
export const options = { thresholds: { checks: ['rate>0.95'] } };
export default function () {
  const list = http.get(`${base}/target/store/api/products`);
  check(list, { 'catalog available': r => r.status === 200 });
  const search = http.get(`${base}/target/store/api/search?q=cloud`);
  check(search, { 'search available': r => r.status === 200 });
  const item = http.get(`${base}/target/store/api/products/101`);
  check(item, { 'product available': r => r.status === 200 });
  // Every 4th synthetic shopper places a bounded order.
  if (__ITER % 4 === 0) {
    const checkout = http.post(`${base}/target/store/api/checkout`,
      JSON.stringify({items:[{product_id:101, quantity:1},{product_id:102, quantity:2}]}),
      {headers:{'Content-Type':'application/json'}});
    check(checkout, { 'fake checkout accepted': r => r.status === 200 });
  }
  sleep(0.7);
}
