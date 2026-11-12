"""Independent containerized k6 worker, authenticated and bounded. One namespace = one source IP."""
import hmac, json, os, signal, subprocess, threading, time, urllib.request, urllib.error
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from pathlib import Path

TOKEN=os.getenv('TOOLBOX_TOKEN',''); NAME=os.getenv('AGENT_NAME','agent'); RESULTS=Path('/tmp/results'); RESULTS.mkdir(exist_ok=True)
lock=threading.RLock(); current={'id':None,'process':None,'state':'idle','summary':None}
class Handler(BaseHTTPRequestHandler):
    def log_message(self,fmt,*args): print(NAME,fmt%args,flush=True)
    def send(self,status,obj):
        data=json.dumps(obj).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def auth(self):return bool(TOKEN) and hmac.compare_digest(self.headers.get('X-Lab-Token',''),TOKEN)
    def do_GET(self):
        if self.path == '/health':return self.send(200,{'ok':True,'agent':NAME})
        if not self.auth():return self.send(403,{'error':'token required'})
        if self.path == '/status':
            with lock:
                p=current['process']; state='running' if p and p.poll() is None else current['state']; report=current['summary']
                return self.send(200,{'agent':NAME,'state':state,'id':current['id'],'summary':report})
        self.send(404,{'error':'unknown route'})
    def do_POST(self):
        if not self.auth():return self.send(403,{'error':'token required'})
        if int(self.headers.get('Content-Length','0'))>2048:return self.send(413,{'error':'large body'})
        try: body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or '{}')
        except Exception:return self.send(400,{'error':'json required'})
        if self.path == '/stop':
            with lock:
                p=current['process']
                if p and p.poll() is None:
                    try:os.killpg(p.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    current['state']='stopping'
            return self.send(200,{'ok':True})
        if self.path != '/start':return self.send(404,{'error':'not found'})
        with lock:
            p=current['process']
            if p and p.poll() is None:return self.send(409,{'error':'already running'})
            url=body.get('url','')
            # Backend sends an already-validated address; the agent also validates it.
            from urllib.parse import urlsplit
            import ipaddress
            parsed=urlsplit(url)
            if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                return self.send(422,{'error':'bad URL'})
            if parsed.hostname!='waf':
                try: ip=ipaddress.IPv4Address(parsed.hostname)
                except Exception:return self.send(422,{'error':'literal IP required'})
                if not ip.is_private or ip.is_link_local or ip.is_loopback:return self.send(422,{'error':'private target only'})
            vus=body.get('vus',0);seconds=body.get('seconds',0);rps=body.get('rps',0)
            if type(vus)!=int or type(seconds)!=int or type(rps)!=int or not 1<=vus<=50 or not 5<=seconds<=120 or not 1<=rps<=100:
                return self.send(422,{'error':'worker resource limits exceeded'})
            run_id=str(int(time.time()))+'-'+NAME
            summary=RESULTS/(run_id+'.json')
            script='/app/k6/worker.js'
            cmd=['/usr/local/bin/k6','run','--vus',str(vus),'--duration',f'{seconds}s','--rps',str(rps),'--summary-export',str(summary),'-e','BASE_URL='+url,script]
            try:p=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT,start_new_session=True)
            except Exception as e:return self.send(503,{'error':str(e)})
            current.update({'id':run_id,'state':'running','process':p,'summary':None})
            def watch():
                p.wait()
                try: result=json.loads(summary.read_text())
                except Exception: result=None
                with lock:current['state']='completed' if p.returncode==0 else 'stopped' if p.returncode in (-15,143) else 'failed';current['summary']=result
            threading.Thread(target=watch,daemon=True).start()
            return self.send(200,{'ok':True,'agent':NAME,'id':run_id,'vus':vus,'seconds':seconds,'rps':rps,'target':url})
ThreadingHTTPServer(('0.0.0.0',8097),Handler).serve_forever()
