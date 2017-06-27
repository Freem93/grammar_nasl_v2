#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85219);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/05 14:41:22 $");

  script_bugtraq_id(55253);
  script_osvdb_id(85054);

  script_name(english:"Atlassian JIRA 4.2.x < 5.1 XSRF");
  script_summary(english:"Checks the version of JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially
affected by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is 4.2.x prior to 5.1.
It is, therefore, potentially affected by a cross-site request forgery
vulnerability, which could allow a remote attacker to trick a victim
into posting issue comments of the attacker's choosing.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2012-08-28
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3417d3d");
  script_set_attribute(attribute:"solution", value:"Upgrade to Atlassian JIRA 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
ver = install['version'];

url = build_url(port:port, qs:dir);
vuln = FALSE;

# Versions 4.2.x < 5.1 are affected
fix = "5.1";
if (
  (ver =~ "^4\.[2-9]|^5\.") &&
  (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
