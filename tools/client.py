"""Separate network-namespace clients for real, independently verifiable IP exercises."""
import http.server, json, os, urllib.request, urllib.error, time, socket, urllib.parse

WAF = os.getenv('WAF_URL','http://waf:8080').rstrip('/')
TOKEN = os.getenv('CLIENT_TOKEN','')
NAME = os.getenv('CLIENT_NAME','client')

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, code, body):
        raw=json.dumps(body).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        if self.path == '/health': return self.reply(200,{'ok':True,'name':NAME})
        if self.headers.get('X-Lab-Token')!=TOKEN or not TOKEN: return self.reply(403,{'error':'internal token required'})
        if self.path.startswith('/probe'):
            t=time.monotonic()
            try:
                req=urllib.request.Request(WAF+'/target/whoami',headers={'User-Agent':'CloudShield-v3-Client-'+NAME})
                with urllib.request.urlopen(req,timeout=6) as r: status,body=r.status,r.read(2048)
            except urllib.error.HTTPError as e: status,body=e.code,e.read(2048)
            except Exception as e: return self.reply(502,{'error':str(e)[:150], 'name':NAME})
            try: data=json.loads(body)
            except Exception: data={'text':body.decode(errors='replace')[:150]}
            return self.reply(200,{'client':NAME,'http_status':status,'body':data,'elapsed_ms':round((time.monotonic()-t)*1000,1),'container_ip':socket.gethostbyname(socket.gethostname())})
        if self.path == '/failed-login':
            outcomes=[]
            for i in range(5):
                req=urllib.request.Request(WAF+'/target/login', data=json.dumps({'username':'student','password':'intentionally-wrong'}).encode(),headers={'Content-Type':'application/json','User-Agent':'CloudShield-v3-Login-Practical-'+NAME},method='POST')
                try:
                    with urllib.request.urlopen(req,timeout=4) as r:outcomes.append(r.status)
                except urllib.error.HTTPError as e:outcomes.append(e.code)
                except Exception as e:outcomes.append(type(e).__name__);break
                time.sleep(.08)
            return self.reply(200,{'client':NAME,'actual_http_statuses':outcomes,'note':'Five real login POSTs generated from independent container address; not a simulated counter'})
        if self.path.startswith('/ips-probe'):
            attack='attack=1' in self.path
            dest='http://toolbox:8096/test'+('?value=LAB_TEST_MARKER' if attack else '?value=ordinary')
            try:
                with urllib.request.urlopen(dest,timeout=3) as r:
                    self.reply(200,{'source':NAME,'http_status':r.status,'blocked_by_network':False,'text':r.read(120).decode(errors='replace')})
            except urllib.error.HTTPError as e:self.reply(200,{'http_status':e.code,'blocked_by_network':False})
            except Exception as e:self.reply(200,{'source':NAME,'blocked_by_network':True,'transport_error':type(e).__name__,'note':'A network timeout/reset may indicate a drop, but Suricata EVE evidence is required for confirmation'})
            return
        if self.path == '/ids-marker':
            # This HTTP request creates genuine TCP data received by the IDS sensor.
            return self.reply(200,{'marker':'LAB_TEST_MARKER','client':NAME})
        self.reply(404,{'error':'unknown route'})

http.server.ThreadingHTTPServer(('0.0.0.0',8098),Handler).serve_forever()
