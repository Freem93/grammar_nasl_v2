#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64438);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2012-4531", "CVE-2012-4532");
  script_bugtraq_id(54259, 55818);
  script_osvdb_id(83490, 87038);

  script_name(english:"Joomla! 2.5.x < 2.5.7 Multiple XSS");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 2.5.x prior to 2.5.7.
It is, therefore, affected by multiple cross-site (XSS) scripting
vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in the
    default_system.php script due to improper validation of
    the User-Agent string before submitting it to the
    sysinfo.php script. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2012-4351)

  - A cross-site scripting (XSS) vulnerability exists in the
    Language Switcher module, specifically within file
    modules/mod_languages/tmpl/default.php, due to improper
    sanitization of input passed via 'PATH_INFO' to the
    index.php script. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2012-4352)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.darksecurity.de/advisories/2012/SSCHADV2012-014.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?611dbe83");
  # https://www.joomla.org/announcements/release-news/5463-joomla-2-5-7-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14e8b065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 2.5.7 or later. Alternatively, apply the
patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

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

fix = "2.5.7";

# Check granularity
if (version =~ "^2(\.5)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "app", port, version);

# Versions 2.5.X less than 2.5.7 are vulnerable
if (version =~ "^2\.5\.[0-6]([^0-9]|$)")
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report,severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
