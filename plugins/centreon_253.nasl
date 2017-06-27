#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80224);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/08 18:22:10 $");

  script_cve_id("CVE-2014-3828", "CVE-2014-3829");
  script_bugtraq_id(70648, 70649);
  script_osvdb_id(
    113499,
    113500,
    113501,
    113502,
    113503,
    113504
  );
  script_xref(name:"EDB-ID", value:"35078");
  script_xref(name:"CERT", value:"298796");

  script_name(english:"Centreon < 2.5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Centreon.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Centreon application hosted on
the remote web server is affected by multiple vulnerabilities :

  - Multiple unauthenticated SQL injection vulnerabilities.
    (CVE-2014-3828)

  - A remote, unauthenticated command injection
    vulnerability in the 'session_id' and 'template_id'
    parameters of the 'displayServiceStatus.php' script.
    (CVE-2014-3829)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://web.archive.org/web/20150215005901/https://documentation.centreon.com/docs/centreon/en/2.5.x/release_notes/centreon-2.5.3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?716aff57");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Oct/78");
  script_set_attribute(attribute:"solution", value:"Upgrade to Centreon 2.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Centreon SQL and Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 2 && ver[1] < 5) ||
  (ver[0] == 2 && ver[1] == 5 && ver[2] < 3)
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 2.5.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
