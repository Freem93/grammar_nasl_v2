#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16197);
 script_version("$Revision: 1.11 $");

 script_bugtraq_id(12290);
 script_osvdb_id(12967, 12968, 13003, 13004, 13005, 13006, 13007);

 script_name(english:"ITA Forum Multiple Scripts SQL Injection");
 script_summary(english:"SQL Injection in ITA Forum");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ITA Forum, a forum software written in PHP.

There is a SQL injection issue in the remote version of this software 
which may allow an attacker to execute arbitrary SQL statements on the
remote host and to potentially overwrite arbitrary files on the remote 
system, by sending a malformed value to several files on the remote 
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/exploits/5AP0A1PELU.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/16");
 script_cvs_date("$Date: 2011/03/12 01:05:15 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

function check(loc)
{
 local_var res;

 res = http_send_recv3(method:"GET", item:string(loc, "/search.php?Submit=true&search=');"), port:port);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
 
 if ( "mysql_fetch_array()" >< res[2] &&
      "Powered by ITA Forum" >< res[2] ) {
	 security_hole(port);
	 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	 exit(0);
	}
}


foreach dir (cgi_dirs()) 
 {
  check(loc:dir);
 }
