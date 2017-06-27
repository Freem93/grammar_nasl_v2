#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94355);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id(
    "CVE-2016-8869",
    "CVE-2016-8870",
    "CVE-2016-9081"
  );
  script_bugtraq_id(
    93883,
    93876,
    93969
  );
  script_osvdb_id(
    146271,
    146272,
    146376
  );
  script_xref(name:"EDB-ID", value:"40637");

  script_name(english:"Joomla! 3.4.4 < 3.6.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 3.4.4 or later but
prior to 3.6.4. It is, therefore, affected by multiple
vulnerabilities :

  - A privilege escalation vulnerability exists in the
    Joomla! core user registration component due to improper
    processing of unfiltered data. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to register an account on a Joomla!
    site with elevated privileges. (CVE-2016-8869)

  - A security bypass vulnerability exists in the Joomla!
    core user registration component due to insufficient
    checks on whether user registration is disabled. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to register an account on a
    Joomla! site even when account registration has been
    disabled. (CVE-2016-8870)

  - A flaw exists in the Joomla! core user modification
    component due to the improper processing of unfiltered
    data. An attacker can exploit this to modify the
    username, password, and user group for existing user
    accounts. (CVE-2016-9081)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5678-joomla-3-6-4-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?deb43b12");
  # https://developer.joomla.org/security-centre/660-20161002-core-elevated-privileges.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80833723");
  # https://developer.joomla.org/security-centre/659-20161001-core-account-creation.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba9590d8");
  # https://developer.joomla.org/security-centre/661-20161003-core-account-modifications.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2094b6a9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/28");

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

dir = install["path"];
install_loc =  build_url(port:port, qs:dir);
version = install['version'];

fix = "3.6.4";

# Pull out the purely numeric version
numeric = eregmatch(string:version, pattern:"^([0-9\.]+)($|[^0-9])");

if (empty_or_null(numeric))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

numeric = numeric[1];

parts = split(numeric, sep:".", keep:FALSE);

if (len(parts) < 3) audit(AUDIT_VER_NOT_GRANULAR, app, version);

if (ver_compare(ver:numeric, fix:fix, strict:FALSE) < 0 &&
    ver_compare(ver:numeric, fix:"3.4.4", strict:FALSE) >= 0)
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
