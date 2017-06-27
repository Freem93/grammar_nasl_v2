#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73274);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/05 14:41:22 $");

  script_osvdb_id(103809);

  script_name(english:"Atlassian JIRA < 6.1.4 Privilege Escalation");
  script_summary(english:"Checks the version of JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is prior to 6.1.4. It
is, therefore, potentially affected by a privilege escalation
vulnerability, which allows a remote, unauthenticated attacker to
commit actions on behalf of any authorized user.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2014-02-26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df77438c");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRA-35797");
  script_set_attribute(attribute:"solution", value:"Upgrade to JIRA 6.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
ver = install['version'];

url = build_url(port:port, qs:dir);

# Check if the host is affected.
fix = "6.1.4";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_warning(port:port, extra:report);
