import h11,pytest

def drain(c):
    out=[]
    for _ in range(64):
        e=c.next_event()
        if e in (h11.NEED_DATA,h11.PAUSED) or isinstance(e,h11.ConnectionClosed):return out
        out.append(e)
    pytest.fail('No input boundary')

@pytest.mark.parametrize('value',[b'0',b'000',b'\t0 ',b' 0\t'])
def test_length_ows_and_leading_zero_consistent(value):
    for strict in (False,True):
        c=h11.Connection(h11.SERVER,strict_request_boundaries=strict)
        c.receive_data(b'POST / HTTP/1.1\r\nHost: local\r\nContent-Length: '+value+b'\r\n\r\n')
        events=drain(c);assert isinstance(events[0],h11.Request) and isinstance(events[-1],h11.EndOfMessage)

def test_strict_stays_enabled_on_second_cycle():
    c=h11.Connection(h11.SERVER,strict_request_boundaries=True)
    c.receive_data(b'GET /ok HTTP/1.1\r\nHost: local\r\n\r\n');drain(c)
    c.send(h11.Response(status_code=200,headers=[(b'Content-Length',b'0')]));c.send(h11.EndOfMessage());c.start_next_cycle()
    c.receive_data(b'POST /bad HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')
    with pytest.raises(h11.RemoteProtocolError):drain(c)
    assert c.their_state is h11.ERROR

@pytest.mark.parametrize('strict',[False,True])
def test_response_parsing_compatibility(strict):
    c=h11.Connection(h11.CLIENT,strict_request_boundaries=strict)
    c.send(h11.Request(method='GET',target='/',headers=[('Host','local')]));c.send(h11.EndOfMessage())
    c.receive_data(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nX-Note: first\r\n second\r\n\r\n0\r\n\r\n')
    events=drain(c);assert isinstance(events[0],h11.Response) and isinstance(events[-1],h11.EndOfMessage)

def test_default_bws_chunk_extension_still_accepted():
    c=h11.Connection(h11.SERVER)
    c.receive_data(b'POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n1 ; label = token\r\nx\r\n0\r\n\r\n')
    events=drain(c);assert b''.join(e.data for e in events if isinstance(e,h11.Data))==b'x'

def test_strict_applies_to_trailer_case_and_fold():
    c=h11.Connection(h11.SERVER,strict_request_boundaries=True)
    c.receive_data(b'POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Test: one\r\n two\r\n\r\n')
    with pytest.raises(h11.RemoteProtocolError,match='obsolete line folding'):drain(c)
    assert c.their_state is h11.ERROR
