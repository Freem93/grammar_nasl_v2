#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77779);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/22 17:06:55 $");

  script_cve_id("CVE-2014-1546");
  script_bugtraq_id(68902);
  script_osvdb_id(109545);

  script_name(english:"Bugzilla < 4.0.14 / 4.2.10 / 4.4.5 / 4.5.5 CSRF Vulnerability");
  script_summary(english:"Checks the Bugzilla version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application affected by a CSRF
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host contains a flaw in its callback APIs in which data is not
properly sanitized before being submitted to the 'jsonrpc.cgi' script.
Using a specially crafted OBJECT element with SWF content, a remote
attacker could perform a cross-site request forgery attack. This could
cause the disclosure of sensitive bug information.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/4.0.13/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 4.0.14 / 4.2.10 / 4.4.5 / 4.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Bugzilla";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

# Versions 3.7.1 to 4.0.13
if ( version =~ "^3\.7\." || version =~ "^4\.0($|\.([0-9]|1[0-3])|rc[12])($|[^0-9])" )
  fix = '4.0.14';
# Versions 4.1.1 to 4.2.9
else if ( version =~ "^4\.1\." || version =~ "^4\.2($|\.[0-9]|rc[12])($|[^0-9])" )
  fix = '4.2.10';
# Versions 4.3.1 to 4.4.4
else if ( version =~ "^4\.3\." || version =~ "^4\.4($|\.[0-4]|rc[12])($|[^0-9])" )
  fix = '4.4.5';
# Versions 4.5.1 to 4.5.4
else if ( version =~ "^4\.5\.[1-4]($|[^0-9])" )
  fix = '4.5.5';
else
  fix = NULL;

if (fix)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

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
