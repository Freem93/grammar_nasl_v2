#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 4000 ) exit(0);


include("compat.inc");


if ( description )
{
  script_id(54844);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 18:02:24 $");

  script_bugtraq_id(46767);
  script_xref(name:"CERT", value:"555316");

  script_name(english:"XMPP Service STARTTLS Plaintext Command Injection");
  script_summary(english:"Tries to inject a command along with STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote instant messaging service allows plaintext command
injection while negotiating an encrypted communications channel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote XMPP service contains a software flaw in its STARTTLS
implementation that could allow a remote, unauthenticated attacker to
inject commands during the plaintext protocol phase that will be
executed during the ciphertext protocol phase.

Successful exploitation could reveal a user's credentials, allowing an
attacker to impersonate them. This could lead to further attacks
involving social engineering."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tools.ietf.org/html/rfc6120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/516901/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor to see if an update is available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("xmpp_starttls.nasl");
  script_require_ports("Services/jabber", 5222);

  exit(0);
}


include("global_settings.inc");
include("x509_func.inc");
include("xmpp_func.inc");


ports = get_kb_list("Services/jabber");
if (isnull(ports)) ports = make_list(5222);

foreach port (ports)
{
  # Ensure the port is open.
  if (!get_port_state(port)) continue;

  # Ensure the port isn't always encrypted.
  encaps = get_kb_item("Transports/TCP/" + port);
  if (encaps && encaps > ENCAPS_IP) continue;

  # Ensure the port supports StartTLS.
  if (!get_kb_item("xmpp/" + port + "/starttls")) continue;

  # Try both client-to-server and server-to-server communication.
  foreach mode (make_list("client", "server"))
  {
    soc = xmpp_open(port:port, mode:mode);
    if (isnull(soc)) continue;

    # Craft exploit.
    c = '<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls" />\n  ';
    if (mode == "client")
      to = get_host_name();
    else
      to = "example.com";
    c += '<nessus />\n';

    # Send exploit.
    send(socket:soc, data:c);

    # Check if server is ready for StartTLS.
    s1 = recv_line(socket:soc, length:1024);
    if (
      !strlen(s1) ||
      "<proceed " >!< s1 ||
      "xml:ns:xmpp-tls" >!< s1
    )
    {
      close(soc);
      continue;
    }

    # Attempt to negotiate an SSL connection.
    soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);
    if (!soc) continue;

    # Try to read the server's response to our injected plaintext.
    s2 = recv_line(socket:soc, length:1024);
    if (isnull(s2)) continue;

    if (report_verbosity > 0)
    {
      report =
        '\n' + 'Nessus sent the following two commands in a single packet :' +
        '\n' +
        '\n' + '  ' + str_replace(find:'\n', replace:'\\n', string:c) +
        '\n' +
        '\n' + 'And the server sent the following two responses :' +
        '\n' +
        '\n' + '  ' + s1 +
        '\n' + '  ' + s2 + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}

exit(0);
