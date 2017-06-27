#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (1/02/09)
# - Added additional CVE and OSVDB refs (1/02/09)
# - Revised script summary (9/6/11)

include("compat.inc");

if(description)
{
 script_id(18362);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2005-1684", "CVE-2005-1685");
 script_bugtraq_id(13692, 13693);
 script_osvdb_id(20684, 20685);

 script_name(english:"Episodex Guestbook Multiple Vulnerabilities (Auth Bypass, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Episodex Guestbook, a guestbook written
in ASP. 

The version of Episodex installed on the remote host does not validate
input to various fields in the 'default.asp' script before using it to
generate dynamic HTML. 

Additionally, an unauthenticated, remote attacker can edit settings by
accessing the application's 'admin.asp' script directly." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/248" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/21");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for unauthenticated access to admin.asp");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

global_var port;

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/admin.asp", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( 'Save Configuration' >< res && 'powered by Sven Moderow\'s GuestBook' >< res )
 {
        security_hole(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
  check(url:dir);


