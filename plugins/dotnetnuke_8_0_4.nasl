#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93197);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_osvdb_id(
    143330,
    143331,
    143332
  );

  script_name(english:"DNN (DotNetNuke) < 8.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of DNN.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of DNN Platform (formerly DotNetNuke) running on the
remote host is affected by multiple vulnerabilities :

  - A flaw exists due to improper validation of user
    permissions. An authenticated, remote attacker with
    permissions to edit a particular page can exploit this
    to make changes to site containers across all pages.
    (VulnDB 143330)

  - A cross-site redirection vulnerability exists due to
    improper validation of links to the registration page
    before returning it to the user. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to follow a crafted link, to redirect the user to a
    malicious website (VulnDB 143331)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker with access to files outside of the root
    of the DNN site, to copy an existing image to any
    location on the server. (VulnDB 143332)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/platform/manage/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN Platform version 8.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

fixed_version = '8.0.4';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
