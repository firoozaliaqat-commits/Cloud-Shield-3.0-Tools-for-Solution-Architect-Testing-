import http from 'k6/http';
import {sleep, check} from 'k6';
export default function() {
 const r=http.get(__ENV.BASE_URL,{timeout:'6s',redirects:0});
 check(r,{'HTTP response received': x => x.status>0 && x.status<500});
 sleep(0.3);
}
