"""Broker-only HTTPS reader. Pinned public addresses, verified TLS and no redirects/proxies."""
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit
from firewall import Denied

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address): super().__init__(host,443,timeout=8,context=ssl.create_default_context()); self.address=address
    def connect(self):
        raw=socket.create_connection((self.address,443),timeout=self.timeout)
        self.sock=self._context.wrap_socket(raw,server_hostname=self.host)


def validate_url(url):
    if not isinstance(url,str) or len(url)>2048: raise Denied('INVALID_PUBLIC_URL')
    try: parsed=urlsplit(url); port=parsed.port
    except ValueError: raise Denied('INVALID_PUBLIC_URL') from None
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or port not in (None,443):
        raise Denied('DESTINATION_DENIED')
    host=parsed.hostname.encode('idna').decode()
    if host=='localhost' or host.endswith(('.localhost','.local','.internal')): raise Denied('DESTINATION_DENIED')
    try:
        addresses=sorted({item[4][0] for item in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)})
        if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses): raise Denied('DESTINATION_DENIED')
    except (socket.gaierror,ValueError): raise Denied('DESTINATION_UNRESOLVED') from None
    return parsed,host,addresses


def fetch_public(url):
    parsed,host,addresses=validate_url(url)
    connection=PinnedHTTPS(host,addresses[0])
    try:
        connection.request('GET',(parsed.path or '/')+('?' + parsed.query if parsed.query else ''),
            headers={'User-Agent':'AgentTrustFirewall/1.0','Accept':'text/html,text/plain','Accept-Encoding':'identity'})
        response=connection.getresponse()
        if response.status!=200: raise Denied('PUBLIC_FETCH_HTTP_'+str(response.status))
        media=response.getheader('Content-Type','').split(';')[0].strip().lower()
        if media not in ('text/html','text/plain') or response.getheader('Content-Encoding','identity') not in ('identity',''):
            raise Denied('PUBLIC_MEDIA_UNSUPPORTED')
        data=response.read(131_073)
        if len(data)>131_072: raise Denied('PUBLIC_RESPONSE_TOO_LARGE')
        return data, 'web.html' if media=='text/html' else 'web.txt'
    except (OSError,http.client.HTTPException): raise Denied('PUBLIC_FETCH_UNAVAILABLE') from None
    finally: connection.close()
