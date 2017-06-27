#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Message-ID: <000001c2deba$8928f000$0200a8c0@r00t3d.net>
# Date: Thu, 27 Feb 2003 15:45:17 -0800
# From: "NGSSoftware Insight Security Research" <mark@ngssoftware.com>
# To: <bugtraq@securityfocus.com>, <ntbugtraq@listserv.ntbugtraq.com>,
#        <vulnwatch@vulnwatch.org>
# Subject: [VulnWatch] ISMAIL (All Versions) Remote Buffer Overrun
#


include("compat.inc");

if(description)
{
 script_id(11272);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-1382");
 script_bugtraq_id(6972);
 script_osvdb_id(51820);

 script_name(english:"ISMail Multiple Command Domain Name Handling Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server (probably ISMail) seems to be vulnerable to a 
buffer overflow which could allow an attacker to gain LOCALSYSTEM 
privileges on this host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q1/0097.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.4.5 of ISMail" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/27");
 script_cvs_date("$Date: 2011/03/11 21:52:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks if the remote mail server can be used to gain a shell"); 
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
banner = smtp_recv_banner(socket:soc);
send(socket:soc, data:'HELP\r\n');
r = smtp_recv_line(socket:soc);

# The typo is _normal_, this is how we recognize ISMail
if("502 Command not implmented" >< r)
{
send(socket:soc, data: 'HELO example.com\r\n');
r = smtp_recv_line(socket:soc);

# This is not a buffer overflow. I doubt anything would crash on that.
send(socket:soc, data: strcat('MAIL FROM: <nessus@', crap(255), '.org>\r\n'));
r = smtp_recv_line(socket:soc);

# Patched version should send an error for such a long domain
if(egrep(pattern:"^250 Action", string:r))security_hole(port);
}
smtp_close(socket: soc);
