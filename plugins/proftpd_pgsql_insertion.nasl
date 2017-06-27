#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11768);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2011/12/05 17:40:21 $");

 script_cve_id("CVE-2003-0500");
 script_bugtraq_id(7974);
 script_osvdb_id(9507);
 
 script_name(english:"PostgreSQL Authentication Module (mod_sql) for ProFTPD USER Name Parameter SQL Injection");
 script_summary(english:"Performs a SQL insertion");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to read or modify arbitrary files on the remote
server.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server is vulnerable to a SQL injection when it
processes the USER command. 

An attacker may exploit this flaw to log into the remote host as any
user.");
 script_set_attribute(attribute:"solution", value:
"If the remote server is ProFTPd, upgrade to ProFTPD 1.2.10.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/19");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if (report_paranoia < 1) exit(0, "This script is prone to False Positive.");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if( ! banner)
 exit(1, "No FTP banner on port "+port);
if ("ProFTPD" >!< banner)
 exit(0, "The FTP server on port "+port+" is not ProFTPD.");

soc = open_sock_tcp(port);
if(!soc)exit(1, "Connection refused on port "+port);

banner = ftp_recv_line(socket:soc);
if (! banner || ! egrep(pattern:"^220.*proftp", string:banner, icase:TRUE) )
{
 close(soc);
 exit(1, "Could not read welcome message on port "+port);
}

send(socket:soc, data:'USER "\r\n');
r = recv_line(socket:soc, length:4096);
close(soc);
if(!r) exit(1, "No answer to bogus USER command on port "+port);

soc = open_sock_tcp(port);
if(!soc)exit(1, "Connection refused on port "+port);
# The following causes a syntax error and makes the FTP
# daemon close the session
banner = ftp_recv_line(socket:soc);
if(!banner)
{
  close(soc);
  exit(1, "Could not read FTP banner on port "+port);
}
send(socket:soc, data: 'USER \'\r\n');
r = recv_line(socket:soc, length:4096, timeout: 3 * get_read_timeout());
if(!r)
{
 security_hole(port);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
close(soc);
