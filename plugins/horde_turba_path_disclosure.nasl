#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  Date: 17 May 2003 13:18:59 -0000
#  From: Lorenzo Manuel Hernandez Garcia-Hierro <security@lorenzohgh.com>
#  To: bugtraq@securityfocus.com
#  Subject: Path Disclosure in Turba of Horde
#


include("compat.inc");

if (description)
{
 script_id(11646);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(7622);
 script_osvdb_id(53370);

 script_name(english:"Horde Turba status.php Path Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the file 'status.php' of this CGI which may allow
an attacker to retrieve the physical path of the remote web root." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/321823" );
 script_set_attribute(attribute:"solution", value:
"Properly set the PHP options 'display_errors' and 'log_errors' to
avoid having PHP display its errors on the web pages it produces." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/21");
 script_cvs_date("$Date: 2011/03/13 23:54:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for status.php");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencies("horde_turba_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde_turba"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 url = string(d, '/status.php');
 r = http_send_recv3(method: 'GET', item:url, port:port);
 if (isnull(r)) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string: r[0]) &&
    egrep(pattern:"/status.php3? on line", string: r[2]))
   {
    security_warning(port);
   }
}
