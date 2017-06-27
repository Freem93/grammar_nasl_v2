#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, reformatted description (6/12/09)


include("compat.inc");

if(description)
{
 script_id(10594);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2001-0126");
 script_bugtraq_id(2295);
 script_osvdb_id(491);

 script_name(english:"Oracle Application Server XSQL Stylesheet Arbitrary Java Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The Oracle XSQL Servlet allows arbitrary Java code to be executed by an
attacker by supplying the URL of a malicious XSLT stylesheet when making
a request to an XSQL page." );
 script_set_attribute(attribute:"solution", value:
"Until Oracle changes the default behavior for the XSQL servlet to 
disallow client supplied stylesheets, use the following workaround. 
Add allow-client-style='no' on the document element of every 
xsql page on the server. This plug-in tests for this vulnerability 
using a sample page, airport.xsql, which is supplied with the Oracle 
XSQL servlet. Sample code should always be removed from production 
servers." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/01/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/09");
 script_cvs_date("$Date: 2014/08/28 03:40:59 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
script_end_attributes();

 
 script_summary(english:"Tests for Oracle XSQL Stylesheet Vulnerability");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Matt Moore");
 script_family(english:"Databases");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
# Check uses a default sample page supplied with the XSQL servlet. 

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/xsql/demo/airport/airport.xsql?xml-stylesheet=none", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("cvsroot" >< r)	
 	security_hole(port);

}
