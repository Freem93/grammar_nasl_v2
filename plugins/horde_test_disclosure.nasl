#
# This script was written by Sverre H. Huseby <shh@thathost.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (1/08/2009)
# - Verbose exits, optimization

include("compat.inc");

if (description)
{
  script_id(11617);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/18 20:40:52 $");

  script_osvdb_id(51217, 51218);

  script_name(english:"Horde test.php Direct Reqest Information Disclosure");
  script_summary(english:"Checks if test.php is available in Horde et al");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote server is running Horde or a related project along with one
or more test scripts.  These scripts may leak server-side information
that is valuable to an attacker.");
  script_set_attribute(attribute:"solution", value:
"Delete the affected scripts or make them unreadable by the web server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


  script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"(C) 2003-2016 Sverre H. Huseby");
  script_family(english:"CGI abuses");

  script_dependencies(
    "http_version.nasl",
    "horde_detect.nasl",
    "imp_detect.nasl", 
    "horde_ingo_detect.nasl",
    "horde_mnemo_detect.nasl",
    "horde_nag_detect.nasl",
    "horde_turba_detect.nasl"
  );
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!can_host_php(port:port)) exit(0, "The web server on port "+port+ "does not support PHP");


files = make_list("/test.php", "/test.php3");


# Generate a list of paths to check.
ndirs = 0;

app_keys = make_list(
  "horde", 
  "imp", 
  "horde_ingo", 
  "horde_mnemo", 
  "horde_nag", 
  "horde_turba"
);
foreach app_key (app_keys)
{
  installs = get_kb_list(string("www/", port, "/", app_key));
  if (installs)
  {
    foreach install (installs)
    {
      matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
      if (!isnull(matches))
      {
        dir = matches[2];
        dirs[ndirs++] = dir;
      }
    }
  }
}

info = "";
foreach d (dirs)
{
  foreach f (files)
  {
    if ("/" == d) url = f;
    else url = string(d, f);

    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if (res == NULL)
      exit(1, "The web server on port "+port+" did not answer");

    if (
      'PHP Version' >< res &&
      (
        'Horde Version' >< res || 
        'IMP Version' >< res ||
        'Ingo Version' >< res ||
        'Mnemo Version' >< res ||
        'Nag Version' >< res ||
        'Turba Version' >< res
      )
    )
    {
      info += '  ' + url + '\n';
      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;
}


if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report = string(
      "\n",
      "Nessus discovered the following test script", s, " :\n",
      "\n",
      info
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
