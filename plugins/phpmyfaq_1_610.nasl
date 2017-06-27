#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24672);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/01/25 01:19:09 $");

  script_cve_id("CVE-2007-1032");
  script_osvdb_id(32603, 50180);

  script_name(english:"phpMyFAQ < 1.6.10 Multiple Script Arbitrary File Upload");
  script_summary(english:"Tries to bypass authentication with phpMyFAQ's ImageManager plugin");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
privilege escalation issues." );
 script_set_attribute(attribute:"description", value:
"The installation of phpMyFAQ on the remote host allows for bypassing
authentication or escalating privileges via the 'admin/attachment.php'
and 'admin/editor/plugins/ImageManager/images.php' scripts.  By
leveraging these issues, a remote attacker can upload files, possibly
even containing arbitrary code, subject to the privileges of the web
server user ID. 

Note that successful exploitation of these issues requires PHP's
'register_globals' setting to be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/advisory_2007-02-18.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyFAQ 1.6.10 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/18");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmyfaq:phpmyfaq");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  script_dependencies("phpmyfaq_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpmyfaq");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Check if we can bypass authentication.
  #
  # nb: we won't actually try to upload a file so that the attack 
  #     is not a destructive one.
  url = string(
    dir, "/admin/editor/plugins/ImageManager/images.php?",
    "auth=1&",
    "permission[addatt]=1"
  );
  r = http_send_recv3(method:"GET",item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if so.
  if (
    "<title>Image List" >< res &&
    "function editImage" >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
