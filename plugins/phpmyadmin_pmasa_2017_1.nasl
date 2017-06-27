#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99280);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/13 13:33:09 $");

  script_cve_id("CVE-2015-8980", "CVE-2016-5702");
  script_bugtraq_id(91380, 95754);
  script_osvdb_id(
    140502,
    143253,
    151006,
    151008,
    151009,
    151011,
    151021
  );

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.19 / 4.4.x < 4.4.15.10 / 4.6.x < 4.6.6 Multiple Vulnerabilities (PMASA-2017-1 - PMASA-2017-7)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.0.x prior to
4.0.10.19, 4.4.x prior to 4.4.15.10, or 4.6.x prior to 4.6.6. It is,
therefore, affected by the following vulnerabilities :

  - An open redirect vulnerability exists due to a failure
    to validate request paths before returning them to
    users. An unauthenticated, remote attacker can exploit
    this, by convincing a user to follow a specially crafted
    link, to redirect the user from the intended legitimate
    website to an arbitrary website of the attacker's
    choosing. (PMASA-2017-1, VulnDB 151006)

  - An arbitrary code execution vulnerability exists in the
    php-gettext component in the select_string() function
    due to improper sanitization of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (PMASA-2017-2, CVE-2015-8980)

  - A denial of service vulnerability exists in the goto()
    function due to improper handling of table data. An
    unauthenticated, remote attacker can exploit this to
    launch a recursive include operation, resulting in a
    denial of service condition. (PMASA-2017-3,
    VulnDB 151008)

  - A flaw exists due to a failure to sanitize input passed
    via cookie parameters. An unauthenticated, remote
    attacker can exploit this to inject arbitrary CSS in
    themes. (PMASA-2017-4, VulnDB 151009)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to inject arbitrary
    values into browser cookies. (PMASA-2017-5,
    CVE-2016-5702)

  - A server-side request forgery vulnerability exists that
    allows an authenticated, remote attacker to bypass
    access restrictions (e.g. host or network ACLs) and
    connect to hosts without the appropriate authorization.
    Note that this vulnerability only affects the 4.6.x
    version branch. (PMASA-2017-6, VulnDB 151021)

  - A denial of service vulnerability exists in the
    replication status functionality due to improper
    handling of specially crafted table names. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (PMASA-2017-7,
    VulnDB 151011)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2017-1/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2017-2/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2017-3/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2017-4/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2017-5/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2017-6/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2017-7/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.0.10.19 / 4.4.15.10 /4.6.6 or later.
Alternatively, apply the patches referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

if (version =~ "^4(\.[046]?$|\.4\.1?[0-9]$|\.0\.1?[0-9])?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.([046])") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.6.x / 4.4.x / 4.0.x", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.6.x < 4.6.6 / 4.4.x < 4.4.15.10 / 4.0.x < 4.0.10.19
cut_off = NULL;
fixed_ver = NULL;
if (version =~ "^4\.0\.")
{
  cut_off = '4.0.0';
  fixed_ver = '4.0.10.19';
}
else if (version =~ "^4\.4\.")
{
  cut_off = '4.4.0';
  fixed_ver = '4.4.15.10';
}
else if (version =~ "^4\.6\.")
{
  cut_off = '4.6.0';
  fixed_ver = '4.6.6';
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
}

if (
  ver_compare(ver:version, minver:cut_off, fix:fixed_ver, regexes:re) == -1
)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
