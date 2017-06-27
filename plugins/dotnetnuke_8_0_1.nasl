#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90198);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_osvdb_id(
    135991,
    135992,
    135993,
    135994,
    135995
  );

  script_name(english:"DNN (DotNetNuke) < 8.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of DNN.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of DNN Platform (formerly DotNetNuke) running on the
remote host is affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of input to the 'returnurl' query
    string parameter before returning it to users. A remote
    attacker can exploit this, via a crafted request, to
    execute arbitrary script code in a user's browser
    session. (VulnDB 135991)

  - A flaw exists due to the WebAPI not properly verifying
    the RequestVerificationToken when handling HTTP POST
    requests to perform sensitive actions. A remote attacker
    can exploit this, by convincing a user to follow a
    crafted link, to carry out a cross-site request forgery
    (XSRF) attack. (VulnDB 135992)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper sanitization of input to the biography field in
    the user profile before returning it to users. An
    authenticated, remote attacker can exploit this, via a
    crafted request, to execute arbitrary script code in a
    user's browser session. (VulnDB 135993)

  - A cross-site scripting (XSS) vulnerability exists, when
    the SSL Client redirect is enabled, due to improper
    validation of the input to URL query string parameters
    before returning it to users. A remote attacker can
    exploit this, via a crafted request, to execute
    arbitrary script code in a user's browser session.
    (VulnDB 135994)

  - A flaw exists due to improper validation of input to
    the 'returnurl' query string parameter. An attacker can
    exploit this, by convincing a user to follow a crafted
    link, to redirect the user to an arbitrary website of
    the attacker's choosing. (VulnDB 135995)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/platform/manage/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN Platform version 8.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

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

fixed_version = '8.0.1';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xss:TRUE, xsrf:TRUE
);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
