#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Changes by Tenable:
#  - Improved description.
#  - Adjusted version regex.
#  - Streamlined code.
#  - Updated cross references.

#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(18357);
 script_cve_id("CVE-2005-1008");
 script_bugtraq_id(12958);
 script_osvdb_id(15190);
 script_version("$Revision: 1.19 $");
 script_name(english:"ASP-DEv XM Forum post.asp IMG Tag XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is vulnerable to a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running the ASP-DEV XM Forum. 

There is a flaw in the remote software that may allow anyone to inject
arbitrary HTML and script code through the BBCode IMG tag to be
executed in a user's browser within the context of the affected web
site." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/31");
 script_cvs_date("$Date: 2015/01/23 22:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "ASP-DEV XM Forum IMG Tag Script Injection Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2015 Josh Zlatin-Amishav");
 script_family(english:"CGI abuses : XSS");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_asp(port:port)) exit(0);

global_var port;

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/default.asp", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(1, "The web server on port "+port+" failed to respond.");
 if ( res =~ '<a href="http://www\\.asp-dev\\.com">Powered by ASP-DEv XM Forums RC [123]<' )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}

