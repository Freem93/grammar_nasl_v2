#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81424);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id("CVE-2014-8630");
  script_bugtraq_id(72525);
  script_osvdb_id(117490);

  script_name(english:"Bugzilla < 4.0.16 / 4.2.12 / 4.4.7 / 5.0rc1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Bugzilla version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla running on the remote 
host is potentially affected by the following vulnerabilities :

  - A command injection vulnerability exists due to a
    failure to properly utilize the 3 arguments form for
    open(). This allows an authenticated, remote attacker
    with 'editcomponents' permission, to inject commands
    into attributes. (CVE-2014-8630)

  - An information disclosure vulnerability exists in the
    WebServices API. An attacker can execute imported
    functions from non-WebServices modules.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.bugzilla.org/security/4.0.15/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1079065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1090275");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 4.0.16 / 4.2.12 / 4.4.7 / 5.0rc1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

# Versions <= 4.0.15
if ( version =~ "^[0-3]\." || version =~ "^4\.0($|\.([0-9]|1[0-5])|rc[12])($|[^0-9])" )
  fix = '4.0.16';
# Versions 4.1.1 to 4.2.11
else if ( version =~ "^4\.1\." || version =~ "^4\.2($|\.([0-9]|1[01])|rc[12])($|[^0-9])" )
  fix = '4.2.12';
# Versions 4.3.1 to 4.4.6
else if ( version =~ "^4\.3\." || version =~ "^4\.4($|\.[0-6]|rc[12])($|[^0-9])" )
  fix = '4.4.7';
# Versions 4.5.1 to 4.5.6
else if ( version =~ "^4\.5\.[1-6]($|[^0-9])" )
  fix = '5.0rc1';
else
  fix = NULL;

if (fix)
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
