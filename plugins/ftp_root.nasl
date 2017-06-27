#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10088);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2015/06/09 14:26:10 $");

 script_cve_id("CVE-1999-0527");
 script_osvdb_id(76);
 script_xref(name:"CERT-CC", value:"CA-1993-10");

 script_name(english:"Anonymous FTP Writable root Directory");
 script_summary(english:"Attempts to write on the remote root dir.");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server allows write access to the root directory.");
 script_set_attribute(attribute:"description", value:
"It is possible to write on the root directory of the remote anonymous
FTP server. This allows an attacker to upload arbitrary files which
can be used in other attacks, or to turn the FTP server into a
software distribution point.");
 script_set_attribute(attribute:"solution", value:
"Restrict write access to the root directory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/10/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

vuln = FALSE;

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);

if (! ftp_authenticate(socket:soc, user:login,pass:password))
  exit(1, "Cannot authenticate on port "+port+".");

send(socket:soc, data: 'CWD /\r\n');
a = recv_line(socket:soc, length:1024);

report = 'The command "CWD /" produced the following result :\n\n' +
         a +'\n' +
         '\n----------------------------------------------------\n';

pasv = ftp_pasv(socket:soc);

send(socket:soc, data: 'STOR nessus_test\r\n');
r = recv_line(socket:soc, length:3);

report += 'The command "STOR .nessus_test" produced the following result :\n\n' +
         r +'\n';

if (r == "425"|| r == "150")
{
  vuln = TRUE;
  send(socket:soc,data: 'DELE nessus_test\r\n');
}

ftp_close(socket: soc);

if (vuln)
{
  replace_kb_item(name:"ftp/"+port+"/writable_root", value:"/");
  set_kb_item(name:"ftp/"+port+"/writable_root", value:TRUE);
  set_kb_item(name:"ftp/writable_root", value:TRUE);

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
