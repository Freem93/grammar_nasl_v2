#TRUSTED 0e4ffbe17fe65caa8ca4b33ebea3ec9ef0449cc9ac99fce87d561239c0568a7642bfe3fb77c647eb6e4f24037c3000115a8e979b3b205a86c7732f4edae51b1c557416a2ba7a2c6356bb72c15cf8800efeb57832aac1e5619399c32f2d6b58126b18e08dc76fe84c14dbbd8778afca46e56f67f03d1e8340b95450eef50528bce09a6396fb0e019db2c1fa87bcb0aaac52b8374d5f324b88ed0d2630653bedaabcaeef6c2cabcb162b4b61c1846391cdffad5ae02e0f8c7e23033e4cd15048bfcae9ff534617447a4a495dacab663283a82abf454b73a03f9ea65e250dcdacf1628e0dc8e39b293a836830f0ae77fba576f115a0350af769e540fadbdf50c88b4e002e71f303927fcabcf7df36c2b6edb0df6d16c71c8aa2fc1d46078cb2ed7c6903bc2a8e906f2f6c2b3dd569ddc0d36050d507d4f88df4465406c0fd70fbc5264afba1a60253da8f6f50a420c83b6fd7501794bf23916d2529992b2c5aa01696e68402aa047f92dae513248221fc2eea306a7f0d19ad158df183a1f717cf6b3cd9a6488450be8f1cea49502a48c53056e819116c615874ed05b9764abeb411a812d84b7b1fc2bf073dcac6775fe2c331c7e4547673532d2f432808ba61712ab3305f891f23d51798a49f27f002c5fdca0e0eb37cd4bb78caab8cbbab8c8e22dc88d533b069fe517bc4af47899273f62963c025c8868e76f7238a17c4429b8f
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("socket_redo_ssl_handshake")) exit(1, "socket_redo_ssl_handshake() is not defined.");

include("compat.inc");

if (description)
{
  script_id(42880);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/02/23");

  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_osvdb_id(
    59968,
    59969,
    59970,
    59971,
    59972,
    59973,
    59974,
    60366,
    60521,
    61234,
    61718,
    61784,
    61785,
    61929,
    62064,
    62135,
    62210,
    62273,
    62536,
    62877,
    64040,
    64499,
    64725,
    65202,
    66315,
    67029,
    69032,
    69561,
    70055,
    70620,
    71951,
    71961,
    74335,
    75622,
    77832,
    90597,
    99240,
    100172,
    104575,
    104796
  );
  script_xref(name:"CERT", value:"120541");

  script_name(english:"SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection");
  script_summary(english:"Tries to renegotiate an SSL connection");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote service allows insecure renegotiation of TLS / SSL
connections."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote service encrypts traffic using TLS / SSL but allows a client
to insecurely renegotiate the connection after the initial handshake.
An unauthenticated, remote attacker may be able to leverage this issue
to inject an arbitrary amount of plaintext into the beginning of the
application protocol stream, which could facilitate man-in-the-middle
attacks if the service assumes that the sessions before and after
renegotiation are from the same 'client' and merges them at the
application layer."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/mail-archive/web/tls/current/msg03948.html");
  script_set_attribute(attribute:"see_also", value:"http://www.g-sec.lu/practicaltls.pdf");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc5746");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for specific patch information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");
  exit(0);
}


include("audit.inc");
include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");
include("rsync.inc");


# nb: SSLv2 doesn't support renegotiation.
encapss = make_list(ENCAPS_TLSv1, ENCAPS_SSLv3);

# Certain SSL implementations, when sent a ClientHello with
# a number of ciphers past some threshold, simply close the
# socket. We'll try connecting with the default list that
# OpenSSL uses.
cipherspec = "";
cipherspec += raw_string(0xc0, 0x14);
cipherspec += raw_string(0xc0, 0x0a);
cipherspec += raw_string(0x00, 0x39);
cipherspec += raw_string(0x00, 0x38);
cipherspec += raw_string(0x00, 0x88);
cipherspec += raw_string(0x00, 0x87);
cipherspec += raw_string(0xc0, 0x0f);
cipherspec += raw_string(0xc0, 0x05);
cipherspec += raw_string(0x00, 0x35);
cipherspec += raw_string(0x00, 0x84);
cipherspec += raw_string(0xc0, 0x12);
cipherspec += raw_string(0xc0, 0x08);
cipherspec += raw_string(0x00, 0x16);
cipherspec += raw_string(0x00, 0x13);
cipherspec += raw_string(0xc0, 0x0d);
cipherspec += raw_string(0xc0, 0x03);
cipherspec += raw_string(0x00, 0x0a);
cipherspec += raw_string(0xc0, 0x13);
cipherspec += raw_string(0xc0, 0x09);
cipherspec += raw_string(0x00, 0x33);
cipherspec += raw_string(0x00, 0x32);
cipherspec += raw_string(0x00, 0x9a);
cipherspec += raw_string(0x00, 0x99);
cipherspec += raw_string(0x00, 0x45);
cipherspec += raw_string(0x00, 0x44);
cipherspec += raw_string(0xc0, 0x0e);
cipherspec += raw_string(0xc0, 0x04);
cipherspec += raw_string(0x00, 0x2f);
cipherspec += raw_string(0x00, 0x96);
cipherspec += raw_string(0x00, 0x41);
cipherspec += raw_string(0x00, 0x07);
cipherspec += raw_string(0xc0, 0x11);
cipherspec += raw_string(0xc0, 0x07);
cipherspec += raw_string(0xc0, 0x0c);
cipherspec += raw_string(0xc0, 0x02);
cipherspec += raw_string(0x00, 0x05);
cipherspec += raw_string(0x00, 0x04);
cipherspec += raw_string(0x00, 0x15);
cipherspec += raw_string(0x00, 0x12);
cipherspec += raw_string(0x00, 0x09);
cipherspec += raw_string(0x00, 0x14);
cipherspec += raw_string(0x00, 0x11);
cipherspec += raw_string(0x00, 0x08);
cipherspec += raw_string(0x00, 0x06);
cipherspec += raw_string(0x00, 0x03);

# This value isn't actually a cipher, instead it signals to
# the server that the client supports secure renegotiation.
cipherspec += raw_string(0x00, 0xff);


get_kb_item_or_exit("SSL/Supported");

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# These are status flags to customize the audit trail depending on the
# behaviour of the server.
secure = 0;
negotiated = FALSE;

report = "";
foreach encaps (encapss)
{
  # Create a Client Hello record.
  if (encaps == ENCAPS_SSLv3)
  {
    ssl_name = "SSLv3";
    ssl_ver = raw_string(0x03, 0x00);
  }
  else if (encaps == ENCAPS_TLSv1)
  {
    ssl_name = "TLSv1";
    ssl_ver = raw_string(0x03, 0x01);
  }

  helo = client_hello(
    version    : ssl_ver,
    cipherspec : cipherspec,
    v2hello    : FALSE
  );

  # Open a socket without encapsulation.
  sock = open_sock_ssl(port);
  if (!sock)
    exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

  # Try to negotiate initial SSL connection.
  send(socket:sock, data:helo);
  recs = recv_ssl(socket:sock);
  close(sock);
  if (isnull(recs)) continue;

  # Check for the secure renegotiation extension.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if( isnull(rec))
    continue;

  negotiated = TRUE;
  count = rec["extension_renegotiation_info_renegotiated_connection"];
  if (!isnull(count))
  {
    if (count != 0)
    {
      report +=
        '\n' + ssl_name + ' appears to support secure renegotiation, but' +
        '\nrenegotiated_connection has a value of ' + count + ' instead of zero.' +
        '\n';
    }
    else
    {
      secure++;
    }
    continue;
  }

  # Open a socket with encapsulation.
  sock = open_sock_ssl(port, encaps:encaps);
  if (!sock) continue;
  negotiated = TRUE;

  # Try to renegotiate SSL connection.
  sock = socket_redo_ssl_handshake(sock);
  if (!sock) continue;

  # Some SSL implementations will drop the connection upon 
  # the second successful handhake, as a mitigation.
  # Here we try a third handshake to test such case.
  sock = socket_redo_ssl_handshake(sock);
  if (!sock) continue;

  close(sock);

  # SSL implementation allows insecure renegotiation.
  report +=
    '\n' + ssl_name + ' supports insecure renegotiation.' +
    '\n';
}

if (report == "")
{
  if (!negotiated)
    msg = "rejected every attempt to negotiate";
  else if (secure == max_index(encapss))
    msg = "does not support insecure renegotiation";
  else
    msg = "rejected every attempt to renegotiate";

  exit(0, "Port " + port + " " + msg + ".");
}

security_warning(port:port, extra:report);
