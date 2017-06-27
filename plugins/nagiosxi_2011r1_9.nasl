#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61429);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(51069, 51072);
  script_osvdb_id(
    77763,
    77764,
    77765,
    77766,
    77767,
    77768,
    77769,
    77770
  );

  script_name(english:"Nagios XI < 2011R1.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Nagios XI");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nagios XI hosted on the remote web server is affected
by multiple vulnerabilities :

  - A privilege escalation vulnerability exists in the
    method used to install RPMs.

  - A privilege escalation vulnerability exists in the
    method used to edit crontab files.

  - Multiple reflective cross-site scripting vulnerabilities
    exist due to the failure to sanitize the query strings
    of GET requests.

  - A stored cross-site scripting vulnerability exists in
    the 'reports/myreports.php' script due to the failure to
    sanitize the report name.

An attacker can leverage the cross-site scripting issues by enticing a
user to follow a malicious URL, causing attacker-specified script code
to run inside the user's browser in the context of the affected site. 
Information harvested this way may aid in launching further attacks.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios XI 2011R1.9 build 20111213 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"see_also", value:"http://0a29.blogspot.com/2011/12/0a29-11-4-privilege-escalation.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520876/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://0a29.blogspot.ca/2011/12/0a29-11-3-cross-site-scripting.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520875/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://assets.nagios.com/downloads/nagiosxi/CHANGES-2011.TXT");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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
matches = eregmatch(string:ver, pattern:"^(\d+)R([.\d]+)(?:.*build (\d+))?");
if (isnull(matches) || isnull(matches[1]) || isnull(matches[2]) ||
    isnull(matches[3]))
  exit(1, 'Unable to parse version string for Nagios server on port ' + port + '.');

year = int(matches[1]);
nums = matches[2];
build = int(matches[3]);

# Versions earlier than 2011R1.9 build 20111213 are vulnerable.
fix_y = "2011";
fix_v = "1.9";
fix_b = "20111213";

if (
  build > fix_b ||
  year > fix_y ||
  (year == fix_y && ver_compare(ver:nums, fix:fix_v, strict:FALSE) >= 0)
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix_y + 'R' + fix_v + ' build ' + fix_b +
    '\n';
}
security_warning(port:port, extra:report);
