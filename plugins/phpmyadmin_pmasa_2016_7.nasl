#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88986);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:06:13 $");

  script_cve_id("CVE-2016-2042", "CVE-2016-2043");
  script_bugtraq_id(82097, 82101);
  script_osvdb_id(133791, 133793);

  script_name(english:"phpMyAdmin 4.4.x < 4.4.15.3 / 4.5.x < 4.5.4 Multiple Vulnerabilities (PMASA-2016-6, PMASA-2016-7)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.4.x prior to
4.4.15.3 or 4.5.x prior to 4.5.4. It is, therefore, affected by the
following vulnerabilities :

  - An information disclosure vulnerability exists in the
    AES.php and Rijndael.php scripts that allows a remote
    attacker, via a specially crafted request, to disclose
    the software's installation path. (CVE-2016-2042)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    normalization script when handling a crafted table name
    before returning it to users. An authenticated, remote
    attacker can exploit this, via specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-2043)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-6/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-7/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.4.15.3 / 4.5.4 or later.
Alternatively, apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "phpMyAdmin";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
dir = install['path'];
url = build_url(qs:dir, port:port);
version = install['version'];

if (version =~ "^4(\.[45])?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.[45][^0-9]") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.4.x / 4.5.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.4.x < 4.4.15.3
# 4.5.x < 4.5.4
cut_off = NULL;
fixed_ver = NULL;

if (version =~ "^4\.4\.")
{
  cut_off   = '4.4.0';
  fixed_ver = '4.4.15.3';
}
else if (version =~ "^4\.5\.")
{
  cut_off   = '4.5.0';
  fixed_ver = '4.5.4';
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
}

if (
  ver_compare(ver:version, fix:cut_off, regexes:re) >= 0 &&
  ver_compare(ver:version, fix:fixed_ver, regexes:re) == -1
)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
