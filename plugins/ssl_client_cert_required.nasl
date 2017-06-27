#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91263);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/05/19 21:27:00 $");

  script_name(english:"SSL/TLS Service Requires Client Certificate");
  script_summary(english:"Checks if the service requires a client certificate to establish an SSL/TLS connection.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service requires an SSL client certificate to establish
an SSL/TLS connection." );
  script_set_attribute(attribute:"description", value:
"The remote service encrypts communications using SSL/TLS and requires
a client certificate in order to establish an SSL/TLS connection.");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_client_cert_requested.nasl");
  script_require_keys("Services/ssl_client_cert_requested");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssl_funcs.inc");
include("misc_func.inc");

kb_list = get_kb_list_or_exit("Services/ssl_client_cert_requested/*");
kb_key = branch(keys(kb_list));

port = int(kb_key - "Services/ssl_client_cert_requested/");

info = get_kb_item("Services/ssl_client_cert_requested/" + port);
# shouldn't be possible
if(isnull(info))
  exit(0, "The service on port " + port + " does not request any SSL client certificates.");

# should not be possible, but check anyways
if(!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

vuln = FALSE;
# If it's unknown, open, and not currently detected as SSL / TLS or detected as SSL/TLS using plain text request ...
if (
  (service_is_unknown(port:port) || get_kb_item("PlainTextOnSSL/"+port)) &&
   get_kb_item("Transports/TCP/"+port) == 1
)
  vuln = TRUE;

# check if we get a handshake error when trying to establish and SSL / TLS connection without a client certificate
if(!vuln && defined_func("ssl_get_error") && defined_func("socket_negotiate_ssl_ex"))
{
  foreach encaps (make_list(ENCAPS_SSLv3, ENCAPS_TLSv1, COMPAT_ENCAPS_TLSv11, COMPAT_ENCAPS_TLSv12))
  {
    if (encaps == ENCAPS_SSLv3)
      if('SSLv3' >!< info) continue;
    else if (encaps == ENCAPS_TLSv1)
      if('TLSv1' >!< info) continue;
    else if (encaps == COMPAT_ENCAPS_TLSv11)
      if('TLSv11' >!< info) continue;
    else if (encaps == COMPAT_ENCAPS_TLSv12)
      if('TLSv12' >!< info) continue;

    soc = open_sock_tcp(port, transport:ENCAPS_IP);
    ssl_soc = socket_negotiate_ssl_ex(async:FALSE, socket:soc, transport:encaps);

    ssl_err = ssl_get_error();

    if(ssl_soc) close(ssl_soc);

    if('alert handshake failure'><ssl_err['string'])
    {
      vuln = TRUE;
      break;
    }
  }
}

if(vuln)
{
  info += ' server is listening on this port and requires client certificate verification.\n';
  security_report_v4(port:port, extra:'\n' + info, severity:SECURITY_NOTE);
}
else exit(0, 'The service on port ' + port + ' is known or allows SSL/TLS connections without providing a client certificate.');
