#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86048);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/22 14:19:54 $");

  script_cve_id("CVE-2015-4499");
  script_bugtraq_id(76713);
  script_osvdb_id(127399);

  script_name(english:"Bugzilla < 4.2.15 / 4.4.10 / 5.0.1 Unauthorized Account Creation Vulnerability");
  script_summary(english:"Checks the Bugzilla version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by a
vulnerability that allows the creation of user accounts.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla running on the remote
host contains a flaw that causes input passed via the 'login'
parameter to be truncated, resulting in domain names of email
addresses becoming corrupted. An unauthenticated, remote attacker can
exploit this to create accounts with email accounts that differ from
the original requests.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/4.2.14/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Bugzilla 4.2.15 / 4.4.10 / 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Bugzilla";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

# Versions 2.0 to 4.2.14
if (
  version =~ "^[23]\." ||
  version =~ "^4\.[01]($|\.)" ||
  version =~ "^4\.2($|\.([0-9]|1[0-4])|rc[12])([^0-9]|$)"
) fix = '4.2.15';
# Versions 4.3.1 to 4.4.9
else if (
  version =~ "^4\.3(\.|$)" ||
  version =~ "^4\.4($|\.[0-9]|rc[12])($|[^0-9])"
) fix = '4.4.10';
# Versions 4.5.1 to 5.0
else if (
  version =~ "^4\.[5-9](\.|$)" ||
  version =~ "^5\.0($|\.0|rc[12])($|[^0-9])"
) fix = '5.0.1';
else
  fix = NULL;

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
