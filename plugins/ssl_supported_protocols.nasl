#TRUSTED 62a8d3bffb60c3c2dd7c7ba5629acc5e953983bcb896f228a0e225d7ca6922ab77a12ce9001154b43765d8e15e286f468c08cb543ec3b821fd46fb9dff44838461a8762c9a8bce40cda7608d94773334dc70df72f65171f1d93a58834fb5fe167c35a2ae95d90015271a7cb830fa4f5608295cf707ecb2cc38daee42650cce20cec8787f1ae16708489eaee2ace39ea434e50929778e1559b70ec20ed44898be56d556785108500e07110e1f288ead202eabc1dba8d77fddd8a9e6ad1a9332f11d6d55b1a12b02215608f0c5b0529fc351bdf44be6723ae8c5c16748d9377b87def7c4248967289c586897eaab01eb40ec167a4fb74f341f4c3ce8b22c3a382865ef712d2c58ead04739cbd87559642cf96daf56c8c4fa6c86408f676c670e27a6c6a409ffaea269c3bf7d9a27ce5e4fc56715ae82c7938f2a093be491583d66ecf86f555cf1037f1762425ccc51b0fd325d1c156ebf039a032be053dce1b39abd1a014f96d7e174e0057779eaf2ee7daf36a7c4bb3ec0db03cd8563594f39d2b43cf419c73d3abaf54d42c2600c67de5c5290b756980cfa3f3f78797bc9254f6fd94ee379ff6988655fbdb8636b984d996b47583a3baf4e450e5fcc95b1cfaada0d066d9734a5733fda9638692308ce782b26f189d3c0ac6fd0c1e0f158ec86106abdb002f835cab5413a7371cd7ad17eb7eb3f87ab3ac2a86aa1b9592cb2ad
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62564);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/18");

  script_name(english:"TLS Next Protocols Supported");
  script_summary(english:"Checks which protocols are supported inside TLS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service advertises one or more protocols as being supported
over TLS.");
  script_set_attribute(attribute:"description", value:
"This script detects which protocols are advertised by the remote
service to be encapsulated by TLS connections.

Note that Nessus did not attempt to negotiate TLS sessions with the
protocols shown.  The remote service may be falsely advertising these
protocols and / or failing to advertise other supported protocols.");

  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/draft-agl-tls-nextprotoneg");
  script_set_attribute(attribute:"see_also", value:"https://technotes.googlecode.com/git/nextprotoneg.html");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("acap_func.inc");
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

get_kb_item_or_exit("SSL/Supported");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_SOCK_FAIL, port);

# If it's encapsulated already, make sure it's a type we support.
encaps = get_kb_item("Transports/TCP/" + port);
if (encaps > ENCAPS_IP && (encaps < ENCAPS_SSLv2 || encaps > COMPAT_ENCAPS_TLSv12))
  exit(1, "Port " + port + " uses an unsupported encapsulation method.");

# Determine whether this port uses StartTLS.
starttls = get_kb_list("*/" + port + "/starttls");
starttls = (!isnull(starttls) && max_index(starttls));

# Choose which transports to test.
if (thorough_tests)
{
  versions = make_list(
    ENCAPS_TLSv1,
    COMPAT_ENCAPS_TLSv11,
    COMPAT_ENCAPS_TLSv12
  );
}
else
{
  versions = get_kb_list_or_exit("SSL/Transport/" + port);
}

# This is the Next Protocol Negotiation extension that asks the server to list
# its supported protocols.
npn =
  mkword(13172) + # Extension type
  mkword(0);      # Extension length
len = mkword(strlen(npn));

# Determine which next protocols are supported.
supported = make_list();
foreach encaps (versions)
{
  if (starttls_svc && encaps != ENCAPS_TLSv1) continue;

  # This is a TLS extension, so skip SSL.
  if (encaps == ENCAPS_SSLv2) continue;
  else if (encaps == ENCAPS_SSLv3) continue;
  else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11) ssl_ver = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12) ssl_ver = raw_string(0x03, 0x03);

  # Create a ClientHello record.
  helo = client_hello(
    version       : ssl_ver,
    v2hello       : FALSE,
    extensions    : npn,
    extensionslen : len
  );

  # Connect to the port, issuing the StartTLS command if necessary.
  soc = open_sock_ssl(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port);

  # Send the ClientHello record.
  send(socket:soc, data:helo);
  recs = recv_ssl(socket:soc);
  close(soc);

  # Find and parse the ServerHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if (isnull(rec)) continue;

  # Ensure that the SSL version is what we expect.
  if (rec["version"] != getword(blob:ssl_ver, pos:0)) continue;

  # Merge in the listed protocols to our running list.
  protocols = rec["extension_next_protocol_negotiation"];
  if (!isnull(protocols))
    supported = make_list(supported, protocols);
}

supported = list_uniq(supported);
if (max_index(supported) == 0)
  exit(0, "Port " + port + " did not list any protocols as supported.");

# Stash the list of supported protocols in the KB for future use.
foreach name (supported)
{
  set_kb_item(name:"SSL/Protocols/" + port, value:name);
}

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nThe target advertises that the following protocols are' +
    '\nsupported over SSL / TLS :' +
    '\n' +
    '\n  ' + join(sort(supported), sep:'\n  ') +
    '\n';
}

security_note(port:port, extra:report);
