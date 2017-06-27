#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92871);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(92340, 92342);
  script_osvdb_id(142588, 142589, 142590);

  script_name(english:"Joomla! < 3.6.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is prior to 3.6.1. It
is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in the
    mail component due to improper sanitization of input
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (VulnDB 142588)

  - An information disclosure vulnerability exists in the
    com_content component due to insufficient access control
    list (ACL) checks. A remote attacker can exploit this to
    disclose sensitive information. (VulnDB 142589)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the com_joomlaupdate component due to a failure to
    require multiple steps, explicit confirmation, or a
    unique token when performing certain sensitive actions.
    A remote attacker can exploit this, by convincing a user
    to follow a specially crafted link, to cause the user to
    perform unspecified actions. Note that this issue only
    affects version 3.6.0. (VulnDB 142590)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5665-joomla-3-6-1-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e91ac130");
  # https://developer.joomla.org/security-centre/654-20160803-core-csrf.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7370ce7d");
  # https://developer.joomla.org/security-centre/652-20160801-core-core-acl-violations.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21440bbe");
  # https://developer.joomla.org/security-centre/653-20160802-core-xss-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?239b57c1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("install_func.inc");
include("misc_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
install_loc =  build_url(port:port, qs:install['path']);

fix = "3.6.1";

# Pull out the purely numeric version
numeric = eregmatch(string:version, pattern:"^([0-9\.]+)($|[^0-9])");

if (empty_or_null(numeric))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

numeric = numeric[1];

parts = split(numeric, sep:".", keep:FALSE);

if (len(parts) < 3) audit(AUDIT_VER_NOT_GRANULAR, app, version);

if (ver_compare(ver:numeric, fix:fix, strict:FALSE) < 0 &&
    ver_compare(ver:numeric, fix:"1.6.0", strict:FALSE) >= 0)
{
  report =
    '\n  URL               : ' +install_loc+
    '\n  Installed version : ' +version+
    '\n  Fixed version     : ' +fix;

  # if ver == 3.6.0, then xsrf vuln exists
  xsrf = (numeric == "3.6.0");
  if (!xsrf)
  {
    report += '\n  Note: The Joomla! installation is not affected by the XSRF vulnerability.';
  }

  report += '\n';
  security_report_v4(
    port:port,
    extra:report,
    severity:SECURITY_WARNING,
    xss:TRUE,
    xsrf:xsrf);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
