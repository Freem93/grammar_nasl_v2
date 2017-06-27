#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10083);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2017/02/21 14:37:42 $");

 script_cve_id("CVE-1999-0082");
 script_osvdb_id(73);

 script_name(english:"FTP 'CWD ~root' Command Privilege Escalation");
 script_summary(english:"Attempts to get root privileges.");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a command privilege escalation
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a flaw that may allow a remote
attacker to gain unauthorized privileges. An attacker can exploit this
flaw by issuing a specially crafted request to the 'CWD ~root'
command.");
 # https://web.archive.org/web/20020903230356/http://www.whitehats.com/info/IDS318
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78eedaee");
 script_set_attribute(attribute:"solution", value:
"Disallow FTP login for root, and make sure root's home directory is
not world readable.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1988/11/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ftp:ftp");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ftpcd:ftpcd");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

 script_family(english:"FTP");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_root.nasl");
 script_require_keys("ftp/login", "Settings/ParanoidReport");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

vuln = FALSE;
report = '';

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

wri = get_kb_item("ftp/"+port+"/writable_root");
if (! wri) wri = get_kb_item("ftp/writable_root");

# It the root directory is already writable, then
# we can't do the test
if(wri)exit(0, "The FTP root directory on port "+port+" is already writable.");

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);

b = ftp_recv_line(socket:soc);
d = strcat('USER ', login, '\r\n');
send(socket:soc, data:d);
b = ftp_recv_line(socket:soc);

d = 'CWD ~root\n';
send(socket:soc, data:d);
b = ftp_recv_line(socket:soc);

report = 'The command "CWD ~root" produced the following result :\n\n' +
         b +'\n' +
         '\n----------------------------------------------------\n';

d = strcat('PASS ', password, '\r\n');
send(socket:soc, data:d);
b = ftp_recv_line(socket:soc);

send(socket:soc, data: 'CWD /\r\n');
a = ftp_recv_line(socket:soc);

port2 = ftp_pasv(socket:soc);
if(!port2) exit(1, "Could not determine the FTP passive port.");

soc2 = open_sock_tcp(port2);
if ( ! soc2 ) audit(AUDIT_SOCK_FAIL, port2);

data = 'STOR .nessus_test_2\r\n';
send(socket:soc, data:data);
r = recv_line(socket:soc, length:3);

report += 'The command "STOR .nessus_test_2" produced the following result :\n\n' +
         r +'\n';

close(soc2);

if(r == "425")
{
  vuln = TRUE;
  data = 'DELE .nessus_test_2\r\n';
  send(socket:soc,data:data);
  ftp_recv_line(socket:soc);
}

data = 'QUIT\r\n';

send(socket:soc, data:data);
ftp_recv_line(socket:soc);
close(soc);

if (vuln)
{
  set_kb_item(name:"ftp/"+port+"/root_via_cwd", value:TRUE);

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
