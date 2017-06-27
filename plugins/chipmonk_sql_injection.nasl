#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16319);
 script_bugtraq_id(12456);
 script_osvdb_id(13567, 13568, 13569, 13570, 13571, 13572);
 
 script_version ("$Revision: 1.15 $");
 script_name(english:"Chipmunk Forum Multiple SQL Injections");
 script_summary(english:"Checks if Chipmunk forum is vulnerable to a SQL injection attack");
 
 script_set_attribute( attribute:"synopsis",  value:
"The web application running on the remote host has a SQL injection
vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running Chipmunk, a web-based forum written
in PHP.

The remote version of this software is affected by several SQL
injection vulnerabilities that may allow an attacker to execute
arbitrary SQL statements on the remote SQL database." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2005/Feb/85"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Chipmunk version 1.3 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/07");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if (! can_host_php(port:port)) exit(0);

if (wont_test_cgi(port: port)) exit(0);

foreach dir ( cgi_dirs() )
{
  r = http_send_recv3(port: port, method: 'POST', 
   data: "email='&submit=submit", item: dir + "/getpassword.php", 
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
  if (isnull(r)) exit(0);
  if("<link rel='stylesheet' href='style.css' type='text/css'>Could not get info" >< r[2])
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
