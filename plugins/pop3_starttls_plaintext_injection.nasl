#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 4000 ) exit(0);


include("compat.inc");


if (description)
{
  script_id(52610);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-0411");
  script_bugtraq_id(46767);
  script_osvdb_id(71020, 71946);
  script_xref(name:"CERT", value:"555316");

  script_name(english:"POP3 Service STLS Plaintext Command Injection");
  script_summary(english:"Tries to inject a command along with STLS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote mail service allows plaintext command injection while 
negotiating an encrypted communications channel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote POP3 service contains a software flaw in its STLS
implementation that could allow a remote, unauthenticated attacker to
inject commands during the plaintext protocol phase that will be
executed during the ciphertext protocol phase. 

Successful exploitation could allow an attacker to steal a victim's
email or associated SASL (Simple Authentication and Security Layer)
credentials."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tools.ietf.org/html/rfc2487"
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("pop3_starttls.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("pop3_func.inc");


port = get_service(svc:"pop3", default:110, exit_on_fail:TRUE);
if (!get_kb_item("pop3/"+port+"/starttls"))
{
  if (get_kb_item("pop3/"+port+"/starttls_tested"))
    exit(0, "The POP3 server on port "+port+" does not support STLS.");

  encaps = get_kb_item("Transports/TCP/"+port);
  if (encaps && encaps > ENCAPS_IP) 
    exit(0, "The POP3 server on port "+port+" always encrypts traffic.");
}


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

s = recv_line(socket:soc, length:2048);
if (!strlen(s)) 
{
  close(soc);
  exit(1, "Failed to receive a banner from the POP3 server on port"+port+".");
}


# Send the exploit.
c = 'STLS\r\nCAPA\r\n';
send(socket:soc, data:c);

resp = "";
while (s1 = recv_line(socket:soc, length:2048))
{
  s1 = chomp(s1);
  match = eregmatch(pattern:"^(\+OK|-ERR) ", string:s1, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}

if (resp == "")
{
  close(soc);

  if (strlen(s1)) errmsg = "The POP3 server on port "+port+" sent an invalid response (" + s1 + ").";
  else errmsg = "The POP3 server on port "+port+" failed to respond to a 'STLS' command.";
  exit(1, errmsg);
}
if (toupper(resp) != '+OK') exit(1, "The POP3 server on port "+port+" did not accept the command (", s1, ").");

# nb: finally, we need to make sure the second command worked.
soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);
if (!soc) exit(1, "Failed to negotiate a TLS connection with the POP3 server on port "+port+".");

resp = "";
while (s2 = recv_line(socket:soc, length:2048))
{
  s2 = chomp(s2);
  match = eregmatch(pattern:"^(\+OK|-ERR) ", string:s2, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}
close(soc);

if (strlen(s2) == 0) exit(0, "The POP3 server on port "+port+" does not appear to be affected.");
else
{
  if (resp && "+OK" == toupper(resp))
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
  else exit(0, "The POP3 server on port "+port+" does not appear to be affected as it responded '" + s2 + "'.");
}
