#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86445);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_osvdb_id(128534);

  script_name(english:"DNN (DotNetNuke) < 7.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of DNN.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of DNN installed on the remote host is affected by
multiple vulnerabilities :

  - An unspecified cross-site scripting vulnerability exists
    due to a failure to properly sanitize content used by
    the tabs control. An unauthenticated, remote attacker
    can exploit this to execute arbitrary script code in the
    user's browser session. (VulnDB 128534)

  - A flaw exists in user registration modes due to a
    failure to revalidate that site registration is set to
    'none'. An attacker can exploit this to register spam
    accounts, thus circumventing DNN's protections.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/platform/manage/security-center");
  script_set_attribute(attribute:"solution", value:"Upgrade to DNN version 7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/DNN");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];

install_url = build_url(qs:dir, port:port);

fixed_version = '7.4.2';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
