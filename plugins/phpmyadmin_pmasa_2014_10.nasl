#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77702);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id("CVE-2014-6300");
  script_bugtraq_id(69790);

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.3 / 4.1.x < 4.1.14.4 / 4.2.x < 4.2.8.1 Micro History XSS and XSRF Vulnerabilities (PMASA-2014-10)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
cross-site scripting and cross-site request forgery vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.3, 4.1.x prior to 4.1.14.4, or 4.2.x prior to 4.2.8.1. It is,
therefore, affected by an input-validation error related to the 'micro
history' feature that could allow a DOM-based cross-site scripting
attack that could further lead to cross-site request forgery attacks.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-10.php");
  # https://github.com/phpmyadmin/phpmyadmin/commit/33b39f9f1dd9a4d27856530e5ac004e23b30e8ac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ef26e90");

  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 4.0.10.3 / 4.1.14.4 / 4.2.8.1 or later, or apply
the patches from the referenced links.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "www/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "phpMyAdmin";

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:appname, port:port, exit_on_fail:TRUE);
dir = install['dir'];
url = build_url(qs:dir, port:port);
version = install['ver'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);
if (version =~ "^4(\.[012])?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.[012][^0-9]") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.0.x / 4.1.x / 4.2.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.0.x < 4.0.10.3
# 4.1.x < 4.1.14.4
# 4.2.x < 4.2.8.1
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.0\.")
{
  cut_off   = '4.0.0';
  fixed_ver = '4.0.10.3';
}

if (version =~ "^4\.1\.")
{
  cut_off   = '4.1.0';
  fixed_ver = '4.1.14.4';
}

if (version =~ "^4\.2\.")
{
  cut_off   = '4.2.0';
  fixed_ver = '4.2.8.1';
}

# The following should never happen at this
# point, but best to be safe and check anyway.
if (isnull(cut_off) || isnull(fixed_ver))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);

if (
    ver_compare(ver:version, fix:cut_off, regexes:re) >= 0 &&
    ver_compare(ver:version, fix:fixed_ver, regexes:re) == -1
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/' + port + '/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
