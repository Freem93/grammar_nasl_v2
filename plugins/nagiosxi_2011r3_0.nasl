#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60099);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(54262);
  script_osvdb_id(82998, 82999, 83547);

  script_name(english:"Nagios XI < 2011R3.0 Multiple XSS Vulnerabilities");
  script_summary(english:"Checks the version of Nagios XI");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nagios XI hosted on the remote web server fails to
properly sanitize input to multiple web pages.

  - A cross-site scripting vulnerability exists in the
    'view' parameter of the 'perfgraphs/index.php' script.

  - A cross-site scripting vulnerability exists in the 'div'
    parameter of the 'graphexplorer/visApi.php' script.

  - Multiple unspecified cross-site scripting
    vulnerabilities.

An attacker can leverage these issues by enticing a user to follow a
malicious URL, causing attacker-specified script code to run inside
the user's browser in the context of the affected site.  Information
harvested this way may aid in launching further attacks.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios XI 2011R3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"see_also", value:"http://0a29.blogspot.com/2012/06/0a29-12-1-cross-site-scripting.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jul/11");
  script_set_attribute(attribute:"see_also", value:"http://assets.nagios.com/downloads/nagiosxi/CHANGES-2011.TXT");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/nagios_xi");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

app = "Nagios XI";

# Get the ports that web servers have been found on.
port = get_http_port(default:80);

# Get details of the install.
install = get_install_from_kb(appname:"nagios_xi", port:port, exit_on_fail:TRUE);
dir = install["dir"];
ver = install["ver"];
url = build_url(port:port, qs:dir + "/");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, url);

# Extract the numeric portion of the version number, and confirm the
# year.
matches = eregmatch(string:ver, pattern:"^(\d+)R([.\d]+)");
if (isnull(matches) || isnull(matches[1]) || isnull(matches[2]))
  exit(1, 'Unable to parse version string for Nagios server on port ' + port + '.');

year = int(matches[1]);
nums = matches[2];

# Versions earlier than 2011R3.0 are vulnerable.
fix = "3.0";
if (
  year > 2011 ||
  (year == 2011 && ver_compare(ver:nums, fix:fix, strict:FALSE) >= 0)
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 2011R3.0' +
    '\n';
}
security_warning(port:port, extra:report);
