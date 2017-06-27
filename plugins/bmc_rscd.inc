#TRUSTED 065725717769a14e36a6f05292a62fb4363401aaa977c3a407eb72652e4238e0d0364bd9c34009b02d00a4b07fe829eaa0dff1b37b8e3636862ac68c83baa3e4a1c671a858cdde4216d395c79a5a8736a33ee46ece37e8d4d2e3a49a4b746058f6eb863afe863de4db6e545597a3086e1a117f33cddf03de2f90b86c1c867095065049efa378e98e8df0a18114c2ad342ba74d29ea60135416b894e685f7552bdded737e5bc560ddc23a14648adbab95375150bb5ba2ba9972b9dec679f5bdfd9fdce0d329d2c29be73e95fb30919a3736a67fd0e2078976deffe38907afce6d63b97552fd411c1b48f9abf690d4701d241f2584f34487708e4b016b9d431a52be45c18ad6a8f7cb86c2cb23042238a5a7f2a34822495bc31fe86c6acfda90ebf8b2c8624d2c06b7999531e8465534b35095c42266c56aac8f96141fdc6710491545c26fc6431317665a31942488a8041c4effb780ce2ee4c94140b7d668945c6eec5e9ea280ecb833a44e160a80c57fca8abb0424208249bbb1f3f2f1b9c5b5f2dd88a19ad19c06775af53aa48cbd6afeb74f81851de09d7236e0565852059e0558bf6e7e28e7fce47fb4780912dff66ba43f82bfd7885ec51fc4a6e674941d009aa89974b988314f2e498fff6349d7e4be568b04887509fd800788c5639ad5649b49272944319e6ab58d13d5bd8ba129f7533fa40a7df60f68a7f0284b86fe

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision
#

##
# Connects to port and sends the upgrade message and
# then establishes an SSL Connection. This function
# modifies the global 'soc' object.
#
# @param type the protocol type ('TLS' or 'TLSRPC')
# @param port the port to connect to
# @return a new sock with the SSL connection establish
##
function rscd_connect(type, port)
{
  local_var soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (!soc) audit(AUDIT_NOT_LISTEN, "BMC RSCD", port);

  # The protocol requires an upgrade string to indicate
  # network shell or XML RPC.
  send(socket:soc, data:type);
  soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);

  # soc should be null if socket negotiation failed but this
  # appears to be untrustworthy. Use sock error as well.
  if (isnull(soc) || socket_get_error(soc) != NOERR) audit(AUDIT_SSL_FAIL, "TLS", port);

  return soc;
}

##
# Reads in a response from the server. The first four bytes
# indicates how long the message that follows will be.
#
# @param soc the socket to receive drom
# @return the message received from the server
##
function get_netsh_response(soc)
{
  local_var length;
  length = recv(socket:soc, length:4, min:4);
  length = getdword(blob:length, pos:0);
  return recv(socket:soc, length:int(length), min:int(length));
}

##
# Sends data to the server. Appends the provided message
# to the length frame.
#
# @param soc the soc to send on
# @param data the data to send
##
function send_netsh_data(soc, data)
{
  data = mkdword(strlen(data)) + data;
  send(socket:soc, data:data);
}

##
# Frames the payload up into an HTTP POST request
#
# @param payload the XMLRPC payload to send
# @param soc the socket to send on
# @param port the port we are sending to
##
function send_xmlrpc(payload, soc, port)
{
  local_var request =
    'POST /xmlrpc HTTP/1.1\r\n' +
    'Host: ' + get_host_ip() + ':' + port + '\r\n' +
    'User-Agent: Nessus\r\n' +
    'Content-Type: text/xml\r\n' +
    'Content-Length: ' + len(payload) + '\r\n\r\n' + payload;
  send(socket:soc, data:request);
}

##
# Sends an intro message in the XML RPC format. We attempt to
# introduce ourselves as the fake user "Nessus Scan". We also
# parse the response to ensure that the responder is RSCD.
#
# @param soc the socket connected to rscd
# @port port the port we are sending to
# @return the servers response. NULL if the server terminated
# the connection or responded with NSH/no auth (ie ACL failure)
##
function send_xml_intro(soc, port)
{
  local_var payload, resp;

  # Send an "intro" request - which is basically "I'm this user"
  payload = '<?xml version="1.0" encoding="UTF-8"?>\n' +
   '<methodCall>\n' +
   '  <methodName>RemoteServer.intro</methodName>\n' + 
   '    <params>\n' +
   '      <param><value>1</value></param>\n' +
   '      <param><value>2</value></param>\n' + 
   '      <param><value>0;0;b;Nessus Scan;2;CM;-;-;0;-;1;1;b;Nessus Scan;CP1252;</value></param>\n' +
   '      <param><value>8</value></param>\n' +
   '    </params>\n' +
   '</methodCall>';
  send_xmlrpc(payload:payload, soc:soc, port:port);

  resp = recv(socket:soc, length:1024);
  if (isnull(resp) || "HTTP" >!< resp || "No authorization to access host" >< resp) return NULL;
  else if ("Server: XMLRPC++" >!< resp)
  {
    close(soc);
    audit(AUDIT_NOT_DETECT, "BMC RSCD", port);
  }

  return resp;
}

function decompress_payload(resp)
{
  local_var end_of_header, compressed_data_start;
  if (isnull(resp) || 'Content-Encoding: gzip\r\n' >!< resp || '\r\n\r\n' >!< resp) return NULL;

  # decompress the payload
  end_of_header = strstr(resp, '\r\n\r\n');
  compressed_data_start = substr(end_of_header, 4);
  return gunzip(compressed_data_start);
}
