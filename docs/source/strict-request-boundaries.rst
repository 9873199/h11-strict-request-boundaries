Strict request boundary mode
-----------------------------

By default h11 preserves its historical, lenient parsing behavior. A
server-side :class:`Connection` can instead be created with
``strict_request_boundaries=True`` to enforce the stricter message
framing rules from `RFC 9112 <https://www.rfc-editor.org/rfc/rfc9112>`_
on inbound requests. This is aimed at gateways and proxies that need to
reject ambiguous messages themselves rather than forwarding them and
discovering later that two HTTP processors disagree about where a
request ends.

In this mode, receiving any of the following raises
:class:`RemoteProtocolError` and moves the connection to
:data:`ERROR`, so data pipelined behind the bad request can never be
delivered as a new request:

* a request carrying both ``Transfer-Encoding`` and
  ``Content-Length`` (the framing is ambiguous);
* more than one ``Content-Length`` field, even when the values agree;
* obsolete header line folding (continuation lines);
* a ``Content-Length`` value that is not a single bare run of decimal
  digits with no trailing or embedded whitespace, signs or comma lists;
* a chunk line carrying an extension or stray optional whitespace;
* a ``Host``, ``Content-Length`` or ``Transfer-Encoding`` field in a
  chunked trailer section.

The mode only affects requests received from a remote client. Response
parsing on client connections and all outbound serialization keep their
previous behavior, so enabling the flag never changes what h11 sends.
