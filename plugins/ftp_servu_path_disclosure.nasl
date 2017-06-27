#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11392);
 script_version ("$Revision: 1.26 $");

 script_cve_id("CVE-2000-0176", "CVE-1999-0838");
 script_bugtraq_id(859, 1016);
 script_osvdb_id(11278, 13632);
 
 script_name(english:"Serv-U < 2.5e Multiple Vulnerabilities (OF, Path Disc)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server discloses the full path to its root through a
CWD command for a nonexistent directory. 

In addition, the server may be prone to a buffer overflow that may
allow a remote, authenticated attacker to launch a denial of service
attack against the affected software." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Dec/29" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Mar/10" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U 2.5e or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/12/02");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "FTP path disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/servu", "ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(! login) login="ftp";
if (! pass) pass="test@nessus.com";

 banner = get_ftp_banner(port:port);
 if ( ! banner || "Serv-U FTP Server" >!< banner ) exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:pass))
 {
   send(socket:soc, data:string("CWD ", rand(), rand(), "-", rand(), "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(egrep(pattern:"^550.*/[a-z]:/", string:r, icase:TRUE))security_warning(port);
   ftp_close(socket: soc);
   exit(0);
 }

#
# Could not log in
# 
 r = get_ftp_banner(port: port);
if(egrep(pattern:"^220 Serv-U FTP-Server v2\.(([0-4])|(5[a-d]))", string:r))
 	security_warning(port);
