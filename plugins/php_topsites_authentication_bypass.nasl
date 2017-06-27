#
# Josh Zlatin-Amishav GPLv2 
#
# Changes by Tenable:
#   - Fixed script name.
#   - Removed unnecessary include of url_func.inc.
#   - security_hole() -> security_warning().
#   - update title, added OSVDB ref (3/25/2009)

include("compat.inc");

if(description)
{
 script_id(19495);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(14353);
 script_osvdb_id(1817);

 script_name(english:"PHP TopSites setup.php Administration Authentication Bypass");

 script_set_attribute(attribute:"synopsis", value:
"Sensitive resources can be accessed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP TopSites, a PHP/MySQL-based customizable
TopList script. 

There is a vulnerability in this software which allows an attacker to
access the admin/setup interface without authentication." );
 script_set_attribute(attribute:"see_also", value:"http://exploitlabs.com/files/advisories/EXPL-A-2005-012-PHPTopSites.txt" );
 script_set_attribute(attribute:"solution", value:
"Limit access to admin directory using, eg, .htaccess." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/07");
 script_cvs_date("$Date: 2011/03/15 19:22:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Tries to access setup.php without authentication";

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
 req = http_get(
   item:string(
     dir, "/admin/setup.php"), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( ("<title>PHP TopSites" >< res) && ("function mMOver(ob)" >< res))
 {
        security_hole(port);
        exit(0);
 }
}
