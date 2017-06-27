#TRUSTED 2358a213378dd080331c1e9470ff3d8a6bc045727fccfdd11565a24863203ef535c996ef1a0868581919fcbe0bd75ea72af4c77538763a52c425884ff6058afe65ed6d5636f5be58596f99b6f01ab507d0cdd0131ca9145a48079514c5d01c2bcd7448cf772c8f3c6af9c9d4304d94afbae4b20a3437abd8373b2ea24e89c970ed005568edaa6cd061253e06e10d53aba711422166af2eb5b1ecdb43a2672953089f8af933ad11e9acacab95c7a9e077ddb02658424f775bb2bbf5eab891c35ff7158c78b70f52bc79be1d22bdd877dda574ffeed51b926a162e35812c9db8095627bbca981f0eaa72e0eb08d47ea31b19485144282eb4817f4af3c6f06eac61f9ffbeb21e5c637c85310d689769922a17873bc0a5eb81ce3a4043c84850488a2500cd9da2bc0fbfb345e6515e0272cb4407924517483d998b03d0cbde2268c9ae168ca9c6b0a93b2be6585687ffdb6542c79e97cf6a1e684e9b79369015081365419c359838158668f29f1e693d19754f3b090bb5031aa0515b6b19f00aabff477c3f8d4e67db60a6076d8ccee83ca6a88cd9d94e3489d6c47de2258db713fbc394454bca51937f3965b3fca859baf9980d1f16131f7ff9e86fc81c55e574309953771dd81b7fa7f08e1891a436e4e5247bbfed03c740cc0192da5d7989383ed4a19975f6e88e1f3869ec3c929d69d4135d75a810ee6dd4cc967c6d40f9ba73
# @DEPRECATED@
#
# This script has been deprecated as the security implications of the
# issue are in dispute; eg, see the CVE entry.
#
# Disabled on 2013/04/29.
#

#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("socket_redo_ssl_handshake")) exit(1, "socket_redo_ssl_handshake() is not defined.");


include("compat.inc");


if (description)
{
  script_id(53491);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/18");

  script_cve_id("CVE-2011-1473");
  script_bugtraq_id(48626);
  script_osvdb_id(73894);

  script_name(english:"SSL / TLS Renegotiation DoS");
  script_summary(english:"Tries to repeatedly renegotiate an SSL connection");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote service allows repeated renegotiation of TLS / SSL
connections."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote service encrypts traffic using TLS / SSL and permits
clients to renegotiate connections.  The computational requirements
for renegotiating a connection are asymmetrical between the client and
the server, with the server performing several times more work.  Since
the remote host does not appear to limit the number of renegotiations
for a single TLS / SSL connection, this permits a client to open
several simultaneous connections and repeatedly renegotiate them,
possibly leading to a denial of service condition."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ietf.org/mail-archive/web/tls/current/msg07553.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor for specific patch information."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");
  exit(0);
}

# Deprecated.
exit(0, "The security implications of this are disputed.");



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

# This value isn't actually a cipher. Instead it signals to
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

# The number of renegotiations required before we decide that a port
# is vulnerable.
max_reneg = 3;

# These are status flags to customize the audit trail depending on the
# behaviour of the server.
negotiated = FALSE;
renegotiated = FALSE;

vuln_encaps = make_list();
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

  # Open a socket without encapsulation.
  sock = open_sock_ssl(port);
  if (!sock)
    exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

  # Try to negotiate initial SSL connection.
  sock = socket_negotiate_ssl(socket:sock, transport:encaps);
  if (!sock) continue;
  negotiated = TRUE;

  # Try to repeatedly negotiate an SSL connection.
  for (attempts = 0; attempts < max_reneg; attempts++)
  {
    sock = socket_redo_ssl_handshake(sock);
    if (!sock) break;
    renegotiated = TRUE;
  }

  # Close the socket if it's still open.
  if (sock) close(sock);

  # This encapsulation is not vulnerable if we were prevented from
  # performing as many renegotiations as we wanted to.
  if (attempts == max_reneg)
    vuln_encaps = make_list(vuln_encaps, ssl_name);
}

if (max_index(vuln_encaps) == 0)
{
  if (!negotiated)
    msg = "rejected every attempt to negotiate";
  else if (!renegotiated)
    msg = "rejected every attempt to renegotiate";
  else
    msg = "eventually rejected our attempts to renegotiate";

  exit(0, "Port " + port + " " + msg + ", and is therefore not vulnerable to renegotiation DoS over SSL / TLS.");
}

security_warning(port:port, extra:'\nThe remote host is vulnerable to renegotiation DoS over ' + join(vuln_encaps, sep:' / ') + '.\n');
