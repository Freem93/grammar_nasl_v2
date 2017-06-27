#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95916);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id(
    "CVE-2016-9836",
    "CVE-2016-9837",
    "CVE-2016-9838"
  );
  script_bugtraq_id(
    94663,
    94892,
    94893
  );
  script_osvdb_id(
    148256,
    148759,
    148781
  );

  script_name(english:"Joomla! < 3.6.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is prior to 3.6.5. It
is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the JFilterInput::isFileSafe() function
    due to improper validation of file types and extensions
    of uploaded files before placing them in a
    user-accessible path. An unauthenticated, remote
    attacker can exploit this issue, by uploading a
    specially crafted file using an alternative PHP
    extension and then requesting it, to execute arbitrary
    code with the privileges of the web service. Note that
    this issue affects versions 3.0.0 to 3.6.4.
    (CVE-2016-9836)

  - An information disclosure vulnerability exists in the
    Beez3 com_content article layout override due to
    inadequate access control list (ACL) checks. An
    authenticated, remote attacker can exploit this to
    disclose restricted content. Note that this issue
    affects versions 3.0.0 to 3.6.4. (CVE-2016-9837)

  - A privilege escalation vulnerability exists due to
    improper validation of form data before storing it in
    the session. An authenticated, remote attacker can
    exploit this, via a specially crafted request, to modify
    existing user accounts, such as resetting credentials or
    group assignments. (CVE-2016-9838)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5693-joomla-3-6-5-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ca7356f");
  # https://developer.joomla.org/security-centre/664-20161201-core-elevated-privileges.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7934a324");
  # https://developer.joomla.org/security-centre/665-20161202-core-shell-upload.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c4c5a5e");
  # https://developer.joomla.org/security-centre/666-20161203-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a397aea4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

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

#if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install["path"];
install_loc =  build_url(port:port, qs:dir);
version = install['version'];

fix = "3.6.5";

# Pull out the purely numeric version
numeric = eregmatch(string:version, pattern:"^([0-9\.]+)($|[^0-9])");

if (empty_or_null(numeric))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

numeric = numeric[1];

parts = split(numeric, sep:".", keep:FALSE);

if (len(parts) < 3) audit(AUDIT_VER_NOT_GRANULAR, app, version);

# Version 1.6.0 - 3.6.4 vulnerable to privilege escalation
# https://developer.joomla.org/security-centre/664-20161201-core-elevated-privileges.html
if (ver_compare(ver:numeric, minver:"1.6.0", fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' +install_loc+
    '\n  Installed version : ' +version+
    '\n  Fixed version     : ' +fix+
    '\n';

  security_report_v4(
    port:port,
    extra:report,
    severity:SECURITY_HOLE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
