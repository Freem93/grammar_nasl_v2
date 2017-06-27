#
# (C) Ami Chayun GPLv2
#


include("compat.inc");

if(description)
{
 script_id(16086);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2004-1430");
 script_bugtraq_id(12138);
 script_osvdb_id(12807);
 
 script_name(english:"IBProArcade index.php Arcade Module gameid Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ibProArcade, a web-based score board system
written in PHP.

One of the application's CGIs, index.php, is affected by a SQL
injection vulnerability in the 'gameid' parameter. An attacker may
exploit this flaw to execute arbitrary SQL statements against the
remote database." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Dec/462" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/31");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of a SQL injection in index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Ami Chayun");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/index.php?act=Arcade&do=stats&gameid=1'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if( "SELECT COUNT(s_id) AS amount FROM ibf_games_scores" >< r )
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}

