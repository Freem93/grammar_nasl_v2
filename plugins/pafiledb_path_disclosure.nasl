# 
# (C) Tenable Network Security, Inc.
# 

# This script was written by shruti@tenablesecurity.com
# based on the scripts written by Renaud Deraison.
#
# Reference: y3dips
#


include("compat.inc");

if(description)
{
 script_id(15909);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(11817);
 script_osvdb_id(12264);
 
 script_name(english:"PAFileDB Multiple Script Error Message Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the remote version of paFileDB that may let an
attacker obtain the physical path of the remote installation by
sending a malformed request to one of the scripts 'admins.php',
'category.php', or 'team.php'.  This information may help an attacker
make more focused attacks against the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110245123927025&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/04");
 script_cvs_date("$Date: 2011/03/13 23:54:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for psFileDB path disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("pafiledb_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/pafiledb");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  r = http_send_recv3(method:"GET", item:dir + "/includes/admin/admins.php", port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];
  if("Fatal error: Call to undefined function" >< res)
  {
    security_warning(port);
    exit(0);
  }

  r = http_send_recv3(method:"GET", item:dir + "/includes/admin/category.php", port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];
  if("Fatal error: Call to undefined function" >< res)
  {
    security_warning(port);
    exit(0);
  }

  r = http_send_recv3(method:"GET", item:dir + "/includes/team.php", port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];
  if("failed to open stream:" >< res)
  {
    security_warning(port);
    exit(0);
  }
}
