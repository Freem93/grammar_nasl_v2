#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 4000 ) exit(0);


include("compat.inc");


if ( description )
{
  script_id(54843);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/27 14:49:38 $");

  script_bugtraq_id(46767);
  script_xref(name:"CERT", value:"555316");

  script_name(english:"ACAP Service STARTTLS Plaintext Command Injection");
  script_summary(english:"Tries to inject a command along with STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The directory service allows plaintext command injection while
negotiating an encrypted communications channel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote ACAP service contains a software flaw in its STARTTLS
implementation that could allow a remote, unauthenticated attacker to
inject commands during the plaintext protocol phase that will be
executed during the ciphertext protocol phase.

Successful exploitation could permit an attacker to modify the
contents of the directory and reveal a user's credentials."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.ietf.org/html/rfc2595"
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

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("acap_starttls.nasl");
  script_require_ports("Services/acap", 674);

  exit(0);
}


include("acap_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"acap", default:674, exit_on_fail:TRUE);
if (!get_kb_item("acap/"+port+"/starttls"))
{
  if (get_kb_item("acap/"+port+"/starttls_tested"))
    exit(0, "The ACAP server on port "+port+" does not support STARTTLS.");

  encaps = get_kb_item("Transports/TCP/"+port);
  if (encaps && encaps > ENCAPS_IP)
    exit(0, "The ACAP server on port "+port+" always encrypts traffic.");
}
tag = 0;


# Connect to ACAP server.
soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

# Send the exploit.
++tag;
c = 'nessus1 STARTTLS\r\nnessus2 NOOP\r\n';
send(socket:soc, data:c);

resp = "";
while (s1 = recv_line(socket:soc, length:2048))
{
  s1 = chomp(s1);
  match = eregmatch(pattern:"^nessus"+tag+" (OK|BAD|NO)", string:s1, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}

if (resp == "")
{
  close(soc);

  if (strlen(s1)) errmsg = "The ACAP server on port "+port+" sent an invalid response (" + s1 + ").";
  else errmsg = "The ACAP server on port "+port+" failed to respond to a 'STARTTLS' command.";
  exit(1, errmsg);
}
if (toupper(resp) != 'OK') exit(1, "The ACAP server on port "+port+" did not accept the command (", s1, ").");

# nb: finally, we need to make sure the second command worked.
soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);
if (!soc) exit(1, "Failed to negotiate a TLS connection with the ACAP server on port "+port+".");

++tag;
resp = "";
while (s2 = recv_line(socket:soc, length:2048))
{
  s2 = chomp(s2);
  match = eregmatch(pattern:"^nessus"+tag+" (OK|BAD|NO)", string:s2, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}
close(soc);

if (strlen(s2) == 0) exit(0, "The ACAP server on port "+port+" does not appear to be affected.");
else
{
  if (resp && "OK" == toupper(resp))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + 'Nessus sent the following two commands in a single packet :' +
        '\n' +
        '\n' + '  ' + str_replace(find:'\r\n', replace:'\\r\\n', string:c) +
        '\n' +
        '\n' + 'And the server sent the following two responses :' +
        '\n' +
        '\n' + '  ' + s1 +
        '\n' + '  ' + s2 + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else exit(0, "The ACAP server on port "+port+" does not appear to be affected as it responded '" + s2 + "'.");
}
