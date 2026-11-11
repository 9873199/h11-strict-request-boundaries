import pytest
import h11

PREFIX=b'POST /upload HTTP/1.1\r\nHost: local\r\n'
NEXT=b'GET /must-not-run HTTP/1.1\r\nHost: local\r\n\r\n'
BAD={
 'te-cl':PREFIX+b'Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n',
 'duplicate-cl':PREFIX+b'Content-Length: 1\r\nContent-Length: 1\r\n\r\nx',
 'conflicting-cl':PREFIX+b'Content-Length: 1\r\nContent-Length: 2\r\n\r\nxx',
 'comma-cl':PREFIX+b'Content-Length: 1, 1\r\n\r\nx',
 'folded':PREFIX+b'X-Note: first\r\n second\r\n\r\n',
 'colon-space':PREFIX+b'Content-Length : 1\r\n\r\nx',
}
for key,value in [('signed-plus',b'+1'),('signed-minus',b'-1'),('inner-space',b'1 0'),('decimal',b'1.0'),('hex',b'0x10'),('overlong',b'9'*100)]:BAD[key]=PREFIX+b'Content-Length: '+value+b'\r\n\r\nx'
for key,value in [('extension-double-equals',b'1;key==value'),('extension-no-name',b'1;=value'),('extension-unclosed-quote',b'1;key="value'),('extension-empty',b'1;')]:BAD[key]=PREFIX+b'Transfer-Encoding: chunked\r\n\r\n'+value+b'\r\nx\r\n0\r\n\r\n'
for name in [b'Host',b'Content-Length',b'Transfer-Encoding',b'hOsT']:
 BAD['trailer-'+name.decode()]=PREFIX+b'Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n'+name+b': x\r\n\r\n'

def inspect_reject(wire,parts):
 c=h11.Connection(h11.SERVER,strict_request_boundaries=True);events=[];error=None
 for part in parts:
  try:
   c.receive_data(part)
   for _ in range(64):
    e=c.next_event()
    if e in (h11.NEED_DATA,h11.PAUSED) or isinstance(e,h11.ConnectionClosed):break
    events.append(e)
   else:pytest.fail('Event pump did not reach an input boundary within 64 events')
  except h11.RemoteProtocolError as exc:error=exc;break
 assert error is not None,'invalid request accepted or stalled'
 assert c.their_state is h11.ERROR
 assert not any(isinstance(e,h11.Request) and e.target==b'/must-not-run' for e in events)
 with pytest.raises(h11.RemoteProtocolError):c.next_event()
 assert str(error),'no diagnostic'
 return type(error).__name__,str(error),sum(isinstance(e,h11.Request) for e in events)

@pytest.mark.parametrize('case',list(BAD))
def test_all_cut_positions_reject_and_poison(case):
 wire=BAD[case]+NEXT
 expected=inspect_reject(wire,[wire])
 assert inspect_reject(wire,[bytes([x]) for x in wire])==expected
 for cut in range(1,len(wire)):
  assert inspect_reject(wire,[wire[:cut],wire[cut:]])==expected,(case,cut)

def drain(c):
 events=[]
 for _ in range(64):
  e=c.next_event()
  if e in (h11.NEED_DATA,h11.PAUSED) or isinstance(e,h11.ConnectionClosed):return events,e
  events.append(e)
 pytest.fail('Event pump did not reach an input boundary within 64 events')

@pytest.mark.parametrize('step',[1,2,7,64,10000])
def test_legal_chunked_with_extensions_and_trailer(step):
 wire=PREFIX+b'Transfer-Encoding: chunked\r\n\r\n3;ok="yes"\r\nabc\r\n0\r\nX-Safe: done\r\n\r\n'
 c=h11.Connection(h11.SERVER,strict_request_boundaries=True);events=[]
 for start in range(0,len(wire),step):
  c.receive_data(wire[start:start+step]);events.extend(drain(c)[0])
 assert b''.join(e.data for e in events if isinstance(e,h11.Data))==b'abc'
 assert any(isinstance(e,h11.EndOfMessage) and list(e.headers)==[(b'x-safe',b'done')] for e in events)

def test_two_pipelined_requests():
 wire=b'GET /one HTTP/1.1\r\nHost: local\r\n\r\nGET /two HTTP/1.1\r\nHost: local\r\n\r\n'
 c=h11.Connection(h11.SERVER,strict_request_boundaries=True);c.receive_data(wire)
 events,_=drain(c);assert [e.target for e in events if isinstance(e,h11.Request)]==[b'/one']
 c.send(h11.Response(status_code=200,headers=[(b'Content-Length',b'0')]));c.send(h11.EndOfMessage());c.start_next_cycle()
 events,_=drain(c);assert [e.target for e in events if isinstance(e,h11.Request)]==[b'/two']

def test_continue_and_body():
 c=h11.Connection(h11.SERVER,strict_request_boundaries=True)
 c.receive_data(PREFIX+b'Content-Length: 3\r\nExpect: 100-continue\r\n\r\n');events,_=drain(c)
 assert isinstance(events[0],h11.Request)
 assert c.send(h11.InformationalResponse(status_code=100,headers=[])).startswith(b'HTTP/1.1 100')
 c.receive_data(b'abc');events,_=drain(c);assert b''.join(e.data for e in events if isinstance(e,h11.Data))==b'abc'

def test_default_te_cl_compatibility():
 c=h11.Connection(h11.SERVER);c.receive_data(BAD['te-cl']);events,_=drain(c)
 assert isinstance(events[0],h11.Request) and isinstance(events[-1],h11.EndOfMessage)


# RFC 9112 section 7.1.1 and RFC 9110 quoted-string grammar: these are legal,
# and exercise more than the simplest token-valued extension.
@pytest.mark.parametrize('extension',[
 b';label="a\\\"b"',
 b';label="a\\\\b"',
 b';label="\x80"',
 b' ; label = token',
 b'\t;\tlabel\t=\t"value"',
])
def test_valid_rfc_chunk_extension_forms(extension):
 wire=PREFIX+b'Transfer-Encoding: chunked\r\n\r\n1'+extension+b'\r\nx\r\n0\r\n\r\n'
 c=h11.Connection(h11.SERVER,strict_request_boundaries=True);events=[]
 for value in wire:
  c.receive_data(bytes([value]));events.extend(drain(c)[0])
 assert b''.join(e.data for e in events if isinstance(e,h11.Data))==b'x'
 assert isinstance(events[-1],h11.EndOfMessage)
