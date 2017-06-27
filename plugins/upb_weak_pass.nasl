#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
#   - removed '/upb' from first request string so test is not dependent
#     on a specific installation directory.
#   - actually tested for users.dat content rather than the response code.
#   - revised plugin title, added OSVDB ref (4/9/2009)


include("compat.inc");

if(description)
{
 script_id(19497);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2005-2005", "CVE-2005-2030");
 script_bugtraq_id(13975);
 script_osvdb_id(17374, 20498);

 script_name(english:"Ultimate PHP Board users.dat Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ultimate PHP Board (UPB).

The remote version of this software is prone to a weak password encryption
vulnerability and may store the users.dat file under the web document root
with insufficient access control." );
 script_set_attribute(attribute:"see_also", value:"http://securityfocus.com/archive/1/402506" );
 script_set_attribute(attribute:"see_also", value:"http://securityfocus.com/archive/1/402461" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/16");
 script_cvs_date("$Date: 2011/03/15 19:26:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Tries to get the users.dat file and checks UPB version";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2011 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 # First try to get users.dat
 req = http_get(
   item:string(
     dir, "/db/users.dat"
   ),
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 # nb: records look like:
 #     user_name<~>password<~>level<~>email<~>view_email<~>mail_list<~>location<~>url<~>avatar<~>icq<~>aim<~>msn<~>sig<~>posts<~>date_added<~>id
 if ( egrep(string:res, pattern:"<~>20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]<~>[0-9]+$") )
 {
        security_warning(port);
        exit(0);
 }
}
