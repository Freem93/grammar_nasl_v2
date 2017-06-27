#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62940);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/04 02:28:18 $");

  script_cve_id("CVE-2012-2532");
  script_bugtraq_id(56440);
  script_osvdb_id(87262);
  script_xref(name:"MSFT", value:"MS12-073");
  script_xref(name:"IAVB", value:"2012-B-0111");

  script_name(english:"MS12-073: Vulnerabilities in Microsoft IIS Could Allow Information Disclosure (2733829) (uncredentialed check)");
  script_summary(english:"Checks response from IIS FTP Service");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Microsoft IIS service running on the remote system contains flaws
that could lead to an unauthorized information disclosure."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The FTP service in the version of Microsoft IIS 7.0 or 7.5 on the
remote Windows host is affected by a command injection vulnerability
that could result in unauthorized information disclosure."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-073");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Vista, 2008, 7, and 2008
R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ftp_service");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_dependencies("os_fingerprint.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');
include('audit.inc');

#
# Make sure remote host's OS is Windows
#
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit('Host/OS');
  if ('Windows' >!< os) audit(AUDIT_OS_NOT, 'Windows');
}

port = get_ftp_port(default:21);

if (!get_port_state(port))  audit(AUDIT_PORT_CLOSED, port, 'TCP');
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, 'TCP');

#
# Get FTP server banner
#
banner =  ftp_recv_line(socket:soc);
if ( isnull(banner) ) exit(1, 'Could not retrieve the banner from the FTP service listening on port '+port+'.');

#
# Check FTP banner to make sure it's Microsoft FTP Service
#
if (banner !~ '^2[0-9][0-9]. *.*Microsoft FTP Service')
  exit(0, 'The FTP service on port '+port+' does not appear to be Microsoft FTP Service.');

#
# Send 2 commands in a one packet
#
cmd1 = 'AUTH AAAAAAAA';
cmd2 = 'SYST';
data = cmd1 + '\r\n' + cmd2 + '\r\n';
send(socket:soc, data:data);


#
# Response for the first command (AUTH):
#
# FTP service versions that don't support the AUTH command:
#   - This include the default FTP service for Windows 2008 and Vista.
#   - In this case, the service return: 500 'AUTH <security_mechanism>': command not understood
#   - These versions are not vulnerable.
#
# FTP service versions that support the AUTH command but has not implemented a security mechanism (i.e., TLS) as the
# argument to the AUTH command:
#   - The FTP server return: 504 Security mechanism not implemented.
#
# FTP service versions that support the AUTH command and have implemented the TLS security mechanism, but
# TLS is not enabled/configured on the server:
#   - Microsoft FTP service 7.0 and 7.5 support the AUTH command and implemented the TLS security mechanism.
#   - In response to 'AUTH TLS', the FTP server return: 534 Local policy on server does not allow TLS secure connections.
#
# FTP service versions that support the AUTH command and have implemented the TLS security mechanism, and
# TLS is enabled/configured on the server:
#   - Microsoft FTP service 7.0 and 7.5 support the AUTH command and implemented the TLS security mechanism.
#   - In response to 'AUTH TLS', the FTP server return: 234 AUTH command ok. Expecting TLS Negotiation.
#
res = ftp_recv_line(socket:soc);
if (isnull(res)) audit(code:1, AUDIT_RESP_NOT, port, "an FTP 'AUTH' command", "TCP");

# FTP server that doesn't understand/support the AUTH command is not vulnerable
if (res =~ '^5[0-9][0-9] *.*' + cmd1 + '.*not understood')
  exit(0, "The FTP service listening on port "+port+" does not support the 'AUTH' command, and thus is not affected.");

#
# Since we have specified a bogus AUTH security mechanism, the FTP server is expected to return: 504 Security mechanism not implemented.
#
if (res !~ '^5[0-9][0-9] *Security mechanism not implemented')
  audit(code:1, AUDIT_RESP_BAD, port, "an FTP '"+cmd1+ "' command", "TCP");


#
# Check if there is a response for the second command (SYST)
#
res = ftp_recv_line(socket:soc);

#
# Vulnerable server will process the commands after the AUTH command
#
if (!isnull(res))
{
  # Check the response for the SYST command
  # Expect to see:  215 Windows_NT
  if (res =~ '^2[0-9][0-9]. *Windows') security_warning(port);
  else audit(code:1, AUDIT_RESP_BAD, port, "a FTP 'SYST' command", "TCP");
}
#
# Patched server doesn't process the commands after the AUTH command.
# So there will be no response for the second command
#
else audit(AUDIT_LISTEN_NOT_VULN, 'FTP service', port);
