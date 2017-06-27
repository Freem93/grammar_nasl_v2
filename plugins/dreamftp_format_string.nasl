# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12086);
 script_cve_id("CVE-2004-2074");
 script_bugtraq_id(9800);
 script_osvdb_id(34373);
 script_version ("$Revision: 1.15 $");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote DreamFTP server is vulnerable to a format string attack when
processing the USER command.

An attacker may exploit this flaw to gain a shell on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to DreamFTP 1.03 or newer (when available) or use another FTP
server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'BolinTech Dream FTP Server 1.02 Format String');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_name(english:"DreamFTP Server username Remote Format String");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/04");
 script_cvs_date("$Date: 2015/12/23 21:38:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Logs as a %n");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);


soc = open_sock_tcp(port);
if (! soc) exit(1);

r = ftp_recv_line(socket:soc);
if ( ! r ) exit(1, "Cannot read FTP banner from port "+port+".");

# Recognize DreamFTP thanks to its error message
send(socket:soc, data:'USER ' + rand()  + '\r\n');
r = ftp_recv_line(socket:soc);
if ( ! r ) exit(1, "The FTP server on port "+port+" did not answer to USER.");
send(socket:soc, data:'PASS ' + rand() + '\r\n');
r = ftp_recv_line(socket:soc);
if ( ! r ) exit(1, "The FTP server on port "+port+" did not answer to PASS.");

if ( "530 Not logged in, user or password incorrect!" >< r )
{
 # Overwrite the username buffer
 send(socket:soc, data:'USER ' + crap(data:"%x", length:86) + '%n\r\n');
 r = ftp_recv_line(socket:soc);
 if ( ! r ) exit(1);
 if (egrep(pattern:"^331 Password required for ..$", string:r) ) security_hole(port);
}
