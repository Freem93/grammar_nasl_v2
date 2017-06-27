#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81495);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/25 14:15:04 $");

  script_cve_id(
    "CVE-2014-9571",
    "CVE-2014-9572",
    "CVE-2014-9573",
    "CVE-2014-9624",
    "CVE-2015-1042"
  );
  script_bugtraq_id(71988);
  script_osvdb_id(
    115211,
    115318,
    115319,
    115320,
    117587
  );

  script_name(english:"MantisBT 1.2.x < 1.2.19 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MantisBT.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MantisBT application hosted on
the remote web server is 1.2.x prior to 1.2.19. It is, therefore,
affected by the following vulnerabilities :

  - An XSS vulnerability exists in 'admin/install.php' that
    allows remote attackers to inject arbitrary script data
    via the admin_username or admin_password parameter.
    (CVE-2014-9571)

  - Access to '/*/install.php' is not properly restricted,
    which allows remote attackers to obtain the database
    credentials via the install parameter with the value 4.
    (CVE-2014-9572)

  - A SQLi vulnerability exists in 'manage_user_page.php'
    that allows remote administrators with FILE privileges
    to execute arbitrary SQL commands via the
    MANTIS_MANAGE_USERS_COOKIE cookie. (CVE-2014-9573)

  - A flaw exists that allows remote attackers to obtain an
    unlimited amount of CAPTCHA samples with different
    perturbations for the same challenge. This allows an
    attacker to bypass CAPTCHA testing. (CVE-2014-9624)

  - The 'string_sanitize_url' function in
    'core/string_api.php' uses an incorrect regular
    expresssion, which allows remote attackers to conduct
    open redirect and phishing attacks via a URL with a
    ':/' separator in the return parameter for
    'login_page.php'. (CVE-2015-1042)

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/blog/?p=408");
  script_set_attribute(attribute:"see_also", value:"https://www.mantisbt.org/bugs/changelog_page.php?version_id=238");
  script_set_attribute(attribute:"solution", value:"Upgrade to MantisBT version 1.2.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "MantisBT";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 1.2.x < 1.2.19 are vulnerable
if (ver[0] == 1 && ver[1] == 2 && ver[2] < 19)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.2.19' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
