#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16195);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2014/05/26 00:12:07 $");

 script_cve_id("CVE-2004-0561");
 script_bugtraq_id(8157, 12254);
 script_osvdb_id(12913, 55702, 55703);

 script_name(english:"UMN Gopherd < 3.0.6 Multiple Remote Vulnerabilities");
 script_summary(english:"Determines if gopherd can be used as a proxy");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a Gopher server that is affected by
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the UMN Gopher server.

The remote version of the remote gopher server seems to be vulnerable
to various issues including a buffer overflow and format string, which
may be exploited by an attacker to execute arbitrary code on the
remote host with the privileges of the gopher daemon.");
 script_set_attribute(attribute:"solution", value:"Upgrade to UMN Gopherd 3.0.6 or newer");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service2.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/gopher",70);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include('misc_func.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/gopher");
if ( ! port ) port = 70;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'GET / HTTP/1.0\r\n\r\n');
buf = http_recv_headers3(socket:soc);
close(soc);
if ( strlen(buf) && "GopherWEB" >< buf)
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:'g\t+' + crap(63) + '\t1\nnessus\n');
 r = recv(socket:soc, length:65535);
 if ( ! r ) exit(0);
 close(soc);

 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:'g\t+' + crap(70) + '\t1\nnessus\n');
 r = recv(socket:soc, length:65535);
 if ( ! r ) security_hole(port);
}

