#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65604);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/07 18:43:42 $");

  script_bugtraq_id(57672);
  script_osvdb_id(89842, 89843, 89844, 89845, 89846, 89847, 89893, 89894);

  script_name(english:"Nagios XI < 2012R1.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Nagios XI");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web application affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the self-reported version of Nagios XI, the remote host is
affected by multiple vulnerabilities.  The alertcloud component is
vulnerable to a cross-site scripting attack and the autodiscovery module
has a remote command execution vulnerability."
  );
  # http://packetstormsecurity.com/files/120038/Nagios-XI-2012R1.5b-XSS-Command-Execution-SQL-Injection-CSRF.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?113aa6b7");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Feb/10");
  script_set_attribute(attribute:"see_also", value:"http://assets.nagios.com/downloads/nagiosxi/CHANGES-2012.TXT");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios XI 2012R1.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

# Versions earlier than 2012R1.6 are vulnerable.
fix = "1.6";
if (
  year > 2012 ||
  (year == 2012 && ver_compare(ver:nums, fix:fix, strict:FALSE) >= 0)
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 2012R1.6' +
    '\n';
}
security_warning(port:port, extra:report);
