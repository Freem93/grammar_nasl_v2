#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
# See the Nessus Scripts License for details
#
# admins who installed this patch would necessarily not be vulnerable to CVE-2001-1325
#
# Changes by Tenable:
# - Revised script name (12/19/08)
# - Changed plugin family [plugin covers more than XSS] (5/20/09)
# - Revised plugin description (06/02/2011)


include("compat.inc");

if(description)
{
 script_id(10936);
 script_version ("$Revision: 1.42 $");

 script_cve_id("CVE-2002-0074", "CVE-2002-0148", "CVE-2002-0150");     # lots of bugs rolled into one patch...
 script_bugtraq_id(4476, 4483, 4486);
 script_osvdb_id(3316, 3338, 3339);
 script_xref(name:"MSFT", value:"MS02-018");

 script_name(english:"Microsoft IIS Multiple Vulnerabilities (MS02-018)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"This IIS Server appears to be vulnerable to one of the cross-site 
scripting attacks described in MS02-018. The default '404' file 
returned by IIS uses scripting to output a link to the top level domain
part of the url requested. By crafting a particular URL, it is possible
to insert arbitrary script into the page for execution.

The presence of this vulnerability also indicates that you are 
vulnerable to the other issues identified in MS02-018 (various remote
buffer overflow and cross-site scripting attacks.)" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-018" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b1236eb" );

 script_set_attribute(attribute:"solution", value:"Update your web server");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/04/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/04/10");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 
 script_summary(english:"Tests for IIS XSS via 404 errors");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check makes a request for nonexistent HTML file. The server should return a 404 for this request.
# The unpatched server returns a page containing the buggy JavaScript, on a patched server this has been
# updated to further check the input...

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/blah.htm", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( ! r ) exit(0);
 str1="urlresult";
 str2="+ displayresult +";

 if((str1 >< r) && (str2 >< r))
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
