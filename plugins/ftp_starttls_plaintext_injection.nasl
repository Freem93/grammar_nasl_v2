#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 4000) exit(0);


include("compat.inc");


if (description)
{
  script_id(53847);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2011-1575");
  script_bugtraq_id(46767);
  script_osvdb_id(71855);
  script_xref(name:"CERT", value:"555316");

  script_name(english:"FTP Service AUTH TLS Plaintext Command Injection");
  script_summary(english:"Tries to inject a command along with AUTH TLS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote FTP server allows plaintext command injection while
negotiating an encrypted communications channel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote FTP server contains a software flaw in its AUTH TLS
implementation that could allow a remote, unauthenticated attacker to
inject commands during the plaintext protocol phase that will be
executed during the ciphertext protocol phase. 

Successful exploitation could permit an attacker to modify files on
the FTP server and reveal a user's credentials."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.ietf.org/html/rfc4217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/516901/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor to see if an update is available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("ftp_starttls.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_service(svc:"ftp", default:21, exit_on_fail:TRUE);
if (!get_kb_item("ftp/"+port+"/starttls"))
{
  if (get_kb_item("ftp/"+port+"/starttls_tested"))
    exit(0, "The FTP server on port "+port+" does not support AUTH TLS.");

  encaps = get_kb_item("Transports/TCP/"+port);
  if (encaps && encaps > ENCAPS_IP)
    exit(0, "The FTP server on port "+port+" always encrypts traffic.");
}


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

s = ftp_recv_line(socket:soc);
if (!strlen(s))
{
  close(soc);
  exit(1, "Failed to receive a banner from the FTP server on port "+port+".");
}


# Send the exploit.
c = 'AUTH TLS\r\nFEAT\r\n';
send(socket:soc, data:c);
s1 = ftp_recv_line(socket:soc);
if (strlen(s1)) s1 = chomp(s1);

if (strlen(s1) < 4)
{
  ftp_close(socket:soc);

  if (strlen(s1)) errmsg = "The FTP server on port "+port+" sent an invalid response (" + s1 + ").";
  else errmsg = "The FTP server on port "+port+" failed to respond to a 'AUTH TLS' command.";
  exit(1, errmsg);
}
if (substr(s1, 0, 2) != "234") exit(1, "The FTP server on port "+port+" did not accept the command (" + s1 + ").");

# nb: finally, we need to make sure the second command worked.
soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);
if (!soc) exit(1, "Failed to negotiate a TLS connection with the FTP server on port "+port+".");
s2 = ftp_recv_line(socket:soc);
if (strlen(s2)) s2 = chomp(s2);

ftp_close(socket:soc);

if (strlen(s2) == 0) exit(0, "The FTP server on port "+port+" does not appear to be affected.");
else
{
  if (strlen(s2) >= 3 && substr(s2, 0, 2) == "211")
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
  else exit(0, "The FTP server on port "+port+" does not appear to be affected as it responded '" + s2 + "'.");
}
