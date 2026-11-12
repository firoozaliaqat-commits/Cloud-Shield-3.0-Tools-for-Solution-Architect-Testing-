"""Internal-only fixed-target lab tool worker. Never exposed to the ECS host.
The CloudShield API is the sole expected caller via a per-deployment token.
"""
import ipaddress
import signal
import hmac
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = os.getenv('TOOLBOX_TOKEN', '')
DATA = Path('/data')
BUSY = threading.Lock()
SENSOR_LOCK=threading.RLock()
SENSOR=None
IPS=None
IPS_LOCK=threading.RLock()
SENSOR_LOG=DATA / 'suricata-live' / 'engine.log'
PROBE = 'http://waf:8080/target/whoami'


def inspect_pcap():
    p = DATA / 'suricata' / 'eve.json'
    items = []
    if p.exists():
        for line in p.read_text(errors='replace').splitlines()[-500:]:
            try:
                obj = json.loads(line)
                if obj.get('event_type') == 'alert':
                    items.append({'signature': obj.get('alert', {}).get('signature'), 'src_ip': obj.get('src_ip'), 'timestamp': obj.get('timestamp')})
            except (ValueError, TypeError):
                continue
    return items


def run_suricata():
    if not shutil.which('suricata'):
        return 503, {'error': 'Suricata binary missing from worker image'}
    if not BUSY.acquire(blocking=False):
        return 409, {'error': 'Another Suricata / iperf3 job is running'}
    try:
        dest = DATA / 'suricata'
        dest.mkdir(parents=True, exist_ok=True)
        (dest / 'eve.json').unlink(missing_ok=True)
        cmd = ['suricata', '-r', '/lab/lab-demo.pcap', '-S', '/lab/lab.rules', '-l', str(dest), '--runmode', 'single']
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=80, check=False)
        alerts = inspect_pcap()
        return (200 if p.returncode == 0 else 502), {
            'engine': 'Suricata', 'mode': 'real offline PCAP inspection',
            'exit_code': p.returncode, 'alerts': alerts[-40:],
            'log_tail': (p.stdout + '\n' + p.stderr)[-1800:]
        }
    except subprocess.TimeoutExpired:
        return 504, {'error': 'Suricata processing timed out after 80 seconds'}
    finally:
        BUSY.release()


def live_alerts():
    path=DATA/'suricata-live'/'eve.json'
    alerts=[]
    if not path.exists():return alerts
    try:
        with path.open(encoding='utf-8',errors='replace') as fd:
            lines=fd.readlines()[-350:]
        for line in lines:
            try:
                o=json.loads(line)
                if o.get('event_type')=='alert':
                    a=o.get('alert',{})
                    alerts.append({'timestamp':o.get('timestamp'),'src_ip':o.get('src_ip'),'dest_ip':o.get('dest_ip'),'signature':a.get('signature'),'sid':a.get('signature_id'),'severity':a.get('severity'),'action':a.get('action'),'proto':o.get('proto')})
            except ValueError:pass
    except OSError:pass
    return alerts[-80:]

def sensor_status():
    with SENSOR_LOCK:
        proc=SENSOR
        running=bool(proc and proc.poll() is None)
    return {'engine':'Suricata','mode':'live interface capture eth0 (toolbox namespace)','running':running,'alerts':live_alerts(), 'ips_enabled':False,'scope':'Only packets visible on toolbox eth0; NOT automatic full VPC monitoring', 'last_error':SENSOR_LOG.read_text(errors='replace')[-1600:] if SENSOR_LOG.exists() and not running else None}

def sensor_start():
    global SENSOR
    with SENSOR_LOCK:
        if SENSOR and SENSOR.poll() is None:return sensor_status()
        dest=DATA/'suricata-live';dest.mkdir(parents=True,exist_ok=True)
        SENSOR_LOG.parent.mkdir(parents=True,exist_ok=True)
        log=SENSOR_LOG.open('a')
        cmd=['suricata','-i','eth0','-S','/lab/lab.rules','-l',str(dest),'--runmode','single','-k','none']
        try:SENSOR=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as e:return {'running':False,'error':str(e),'scope':'isolated toolbox network only'}
        finally:log.close()
    time.sleep(0.8)
    return sensor_status()

def sensor_stop():
    global SENSOR
    with SENSOR_LOCK:
        if SENSOR and SENSOR.poll() is None:
            try:os.killpg(SENSOR.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:SENSOR.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(SENSOR.pid,signal.SIGKILL)
    return sensor_status()

def live_test_traffic():
    # The TCP request and response go through toolbox eth0. The harmless rule
    # looks for the actual response string LAB_TEST_MARKER.
    try:
        url='http://client-a:8098/ids-marker'
        with urllib.request.urlopen(urllib.request.Request(url,headers={'X-Lab-Token':TOKEN}),timeout=5) as r:
            data=json.loads(r.read(1024))
        time.sleep(0.7)
        return 200,{'request_sent':True,'response':data,'sensor':sensor_status(),'note':'This was a real HTTP exchange on the monitored namespace. Alert only if EVE has a matching event.'}
    except Exception as e:return 503,{'error':f'Live traffic generation failed: {str(e)[:150]}'}

def run_iperf(config):
    if not BUSY.acquire(blocking=False):return 409,{'error':'Another CPU-intensive job is active'}
    try:
        seconds=int(config.get('seconds',4));host=config.get('ip') or 'iperf3-server'
        port=int(config.get('port',5201));protocol=config.get('protocol','tcp');direction=config.get('direction','upload');streams=int(config.get('streams',1));mbps=int(config.get('mbps',10))
        if not 2<=seconds<=30 or not 1024<=port<=65535 or not 1<=streams<=4 or not 1<=mbps<=100 or protocol not in ('tcp','udp') or direction not in ('upload','download','both'):return 422,{'error':'Parameter outside safe limits'}
        if host!='iperf3-server':
            try:ip=ipaddress.IPv4Address(host)
            except ValueError:return 422,{'error':'Private literal IPv4 address required'}
            if not ip.is_private or ip.is_loopback or ip.is_link_local:return 422,{'error':'Private VPC target only'}
        cmd=['iperf3','-c',host,'-p',str(port),'-t',str(seconds),'-P',str(streams),'--json']
        if protocol=='udp':cmd+=['-u','-b',f'{mbps}M']
        if direction=='download':cmd+=['-R']
        elif direction=='both':cmd+=['--bidir']
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=seconds+12,check=False)
        if p.returncode:return 503,{'engine':'iperf3','error':'Connection or test failed; verify ECS2 iperf3 server and VPC security group','log_tail':(p.stderr+p.stdout)[-800:]}
        x=json.loads(p.stdout);end=x.get('end',{});sent=end.get('sum_sent') or end.get('sum') or {};recv=end.get('sum_received') or end.get('sum') or {}
        if not recv and end.get('streams'):recv=end.get('streams',[{}])[0].get('receiver',{})
        return 200,{'engine':'iperf3','host':host,'port':port,'protocol':protocol,'direction':direction,'streams':streams,'seconds':seconds,'scope':'Docker bridge' if host=='iperf3-server' else 'Cross-ECS VPC (verify VPC routing)', 'sender_mbps':round(float(sent.get('bits_per_second',0))/1e6,2),'receiver_mbps':round(float(recv.get('bits_per_second',0))/1e6,2),'bytes_sent':sent.get('bytes',0),'retransmits':sent.get('retransmits',0),'jitter_ms':recv.get('jitter_ms'),'lost_packets':recv.get('lost_packets'),'lost_percent':recv.get('lost_percent'),'result_source':'iperf3 native JSON','success':True}
    except (subprocess.TimeoutExpired,ValueError,TypeError,OSError) as e:return 503,{'error':f'iperf3 test failed: {type(e).__name__}: {str(e)[:100]}'}
    finally:BUSY.release()


# Optional isolated NFQUEUE IPS experiment. Only port 8096 inside toolbox is
# queued; the toolbox management port 8099 and ECS SSH/dashboard are never affected.
from urllib.parse import urlsplit

def ips_state():
    with IPS_LOCK:
        running=bool(IPS and IPS.poll() is None)
    file=DATA/'suricata-ips'/'eve.json';events=[]
    if file.exists():
        try:
            for line in file.read_text(errors='replace').splitlines()[-200:]:
                try:
                    o=json.loads(line)
                    if o.get('event_type')=='alert':events.append({'action':o.get('alert',{}).get('action'),'signature':o.get('alert',{}).get('signature'),'src_ip':o.get('src_ip')})
                except ValueError:pass
        except OSError:pass
    return {'running':running,'mode':'isolated NFQUEUE IPS only for toolbox:8096','alerts':events[-20:],'note':'Requires NFQUEUE kernel support and NET_ADMIN within toolbox namespace. Never alters host firewall.'}

def ips_rule(action):
    base=['iptables',action,'INPUT','-p','tcp','--dport','8096','-j','NFQUEUE','--queue-num','3','--queue-bypass']
    return subprocess.run(base,capture_output=True,text=True,timeout=4,check=False)

def ips_start():
    global IPS
    with IPS_LOCK:
        if IPS and IPS.poll() is None:return 200,ips_state()
        dest=DATA/'suricata-ips';dest.mkdir(exist_ok=True,parents=True)
        check=subprocess.run(['iptables','-C','INPUT','-p','tcp','--dport','8096','-j','NFQUEUE','--queue-num','3','--queue-bypass'],capture_output=True,text=True,timeout=4)
        if check.returncode:
            rule=ips_rule('-I')
            if rule.returncode:return 503,{'running':False,'error':'NFQUEUE firewall rule unavailable: '+rule.stderr[-250:]}
        log=(dest/'engine.log').open('a')
        try:IPS=subprocess.Popen(['suricata','-q','3','-S','/lab/ips.rules','-l',str(dest),'--runmode','single','-k','none'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        except Exception as e:
            ips_rule('-D')
            return 503,{'running':False,'error':str(e)}
        finally:log.close()
    time.sleep(1.2)
    if IPS.poll() is not None:
        ips_rule('-D')
        return 503,{'running':False,'error':(dest/'engine.log').read_text(errors='replace')[-600:]}
    return 200,ips_state()

def ips_stop():
    global IPS
    with IPS_LOCK:
        if IPS and IPS.poll() is None:
            try:os.killpg(IPS.pid,signal.SIGTERM);IPS.wait(timeout=4)
            except Exception:pass
        ips_rule('-D')
    return 200,ips_state()

class IpsHandler(BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_GET(self):
        content=b'IPS lab request passed normally'
        self.send_response(200);self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content)

def ips_server():
    ThreadingHTTPServer(('0.0.0.0',8096),IpsHandler).serve_forever()

def probe():
    started = time.monotonic()
    try:
        with urllib.request.urlopen(urllib.request.Request(PROBE, headers={'User-Agent':'CloudShield-Real-Probe/2.0'}), timeout=5) as response:
            code = response.status
            body = response.read(1000).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read(1000).decode('utf-8', errors='replace')
    except Exception as e:
        return 503, {'error': f'Actual WAF round-trip failed: {type(e).__name__}: {str(e)[:140]}'}
    try:
        data = json.loads(body)
    except ValueError:
        data = {'response': body[:300]}
    return 200, {'actual_http_status': code, 'response': data, 'elapsed_ms': round((time.monotonic()-started)*1000,1), 'url': '/target/whoami', 'note': 'Request originated from the separate toolbox container, not a mocked UI value'}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print('toolbox:', fmt % args, flush=True)

    def reply(self, code, data):
        data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        if not TOKEN or not hmac.compare_digest(self.headers.get('X-Lab-Token',''), TOKEN):
            self.reply(403, {'error': 'Internal worker token required'})
            return False
        return True

    def do_GET(self):
        if self.path == '/health':
            self.reply(200, {'ok': True, 'suricata_available': bool(shutil.which('suricata')), 'iperf_available': bool(shutil.which('iperf3'))})
        elif self.path == '/suricata/status' and self.authorized():
            self.reply(200,sensor_status())
        elif self.path == '/suricata/ips/status' and self.authorized():
            self.reply(200,ips_state())
        elif self.path == '/probe' and self.authorized():
            self.reply(*probe())
        else:
            self.reply(404, {'error': 'not found'})

    def do_POST(self):
        if not self.authorized():
            return
        if int(self.headers.get('Content-Length', '0')) > 300:
            self.reply(413, {'error':'Payload too long'})
            return
        try:
            request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))) or b'{}')
        except ValueError:
            self.reply(400, {'error':'Invalid JSON'})
            return
        if self.path == '/suricata':
            self.reply(*run_suricata())
        elif self.path == '/suricata/start':
            self.reply(200,sensor_start())
        elif self.path == '/suricata/stop':
            self.reply(200,sensor_stop())
        elif self.path == '/suricata/traffic':
            self.reply(*live_test_traffic())
        elif self.path == '/suricata/ips/start':
            self.reply(*ips_start())
        elif self.path == '/suricata/ips/stop':
            self.reply(*ips_stop())
        elif self.path == '/iperf3':
            self.reply(*run_iperf(request))
        else:
            self.reply(404, {'error':'not found'})


if __name__ == '__main__':
    # Try to start IDS on boot; if capture lacks kernel capability, report an honest error.
    threading.Thread(target=sensor_start,daemon=True).start()
    threading.Thread(target=ips_server,daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0',8099),Handler).serve_forever()
