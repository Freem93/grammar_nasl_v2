#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14318);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/12/22 14:57:47 $");

 script_bugtraq_id(10948);
 script_osvdb_id(8833);
 
 script_name(english:"CuteNews show_archives.php archive Parameter XSS");
 script_summary(english:"Checks for the presence of show_archives.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CuteNews on the remote host is
affected by a cross-site scripting (XSS) vulnerability due to a
failure to sanitize input to the 'archive' parameter of the
show_archives.php script. An unauthenticated, remote attacker can
exploit this, via a specially crafted request, to execute arbitrary
script code in a user's browser session.");
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/12260/");
 script_set_attribute(attribute:"solution", value:"Upgrade to CuteNews v1.3.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/20");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("cutenews_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/cutenews");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if(!can_host_php(port:port)) 
	exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc = matches[2];
  req = http_get(item:string(loc, "/show_archives.php?archive=<script>foo</script>&subaction=list-archive&"),
 		port:port);			
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( r == NULL ) exit(0);
  if("<script>foo</script>" >< r)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
