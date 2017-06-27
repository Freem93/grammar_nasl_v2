#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64690);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/07 18:43:42 $");

  script_bugtraq_id(56761);
  script_osvdb_id(88007, 88008, 88009, 88010);

  script_name(english:"Nagios XI 2011R1.9 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks version of Nagios XI");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web application installed that is affected by
several SQL injection vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:

"The remote host is running Nagios XI 2011R1.9.  This version is
reportedly affected by multiple SQL injection vulnerabilities in the
'hostgroups.php', 'services.php', 'hosts.php', and 'servicegroups.php'
scripts.

Note that exploitation requires that an attacker to be authenticated."
  );
  # http://www.nccgroup.com/en/learning-research-centre/security-testing-audit-compliance-resources/technical-advisories/nagios-xi-network-monitor-blind-sql-injection/#.ULkcoeSE36U
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?843b8b00");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jul/10");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Nov/116");
  script_set_attribute(attribute:"see_also", value:"http://labs.nagios.com/2012/04/13/nagios-xi-ccm-full-beta/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios XI CCM 2012 Full Beta or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/19");

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
matches = eregmatch(string:ver, pattern:"^(\d+)R([.\d]+)(?:.*build (\d+))?");
if (isnull(matches)) exit(1, "Failed to parse the version of the Nagios XI install at "+url+".");

year = int(matches[1]);
nums = matches[2];
build = int(matches[3]);

if (
  year != "2011" ||
  nums != "1.9"
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : Nagios XI CCM Full Beta (2012)' +
    '\n';
}
security_warning(port:port, extra:report);
