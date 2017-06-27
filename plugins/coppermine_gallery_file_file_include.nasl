#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21240);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-1909");
  script_bugtraq_id(17570);
  script_osvdb_id(24744);

  script_name(english:"Coppermine Photo Gallery index.php file Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file using Coppermine Photo Gallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The version of Coppermine Gallery installed on the remote host fails
to properly sanitize input to the 'file' parameter of the 'index.php'
script before using it in a PHP 'include_once()' function.  Regardless
of PHP's 'register_globals' setting, an unauthenticated attacker may
be able to exploit this issue to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431062/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/forum/index.php?topic=30655.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Coppermine version 1.4.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/14");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit a flaw to read the albums folder index.php.
  file = ".//./albums/index";
  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/index.php?", "file=", file));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if the result looks like the albums folder's index.php.
  if ("Albums Folder</title>" >< res)
  {
    security_hole(port);
    exit(0);
  }
}
