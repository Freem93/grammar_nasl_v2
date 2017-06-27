#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73024);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2014-7982", "CVE-2014-7984");
  script_bugtraq_id(66118, 66121);
  script_osvdb_id(104120, 104122);

  script_name(english:"Joomla! 2.5.x < 2.5.19 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation hosted on the remote web server is 2.5.x prior to 2.5.19.
It is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    improper sanitization of input before returning it to
    users. An unauthenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary code in a user's browser session.
    (CVE-2014-7982)

  - A security bypass vulnerability exists that allows a
    remote attacker to bypass intended restrictions and log
    into the system using GMail credentials. (CVE-2014-7984)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5537-joomla-2-5-19-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b322a6d");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security/580-20140303.html");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security/581-20140304.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 2.5.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

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

fix = "2.5.19";

# Check granularity
if (version =~ "^2(\.5)?$") audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Branch Check
if (!(version =~ "^2\.5\.")) exit(0,'The version of Joomla installed at '+install_loc+' is not 2.5.x.');

# Versions 2.5.x < 2.5.19 are vulnerable (There are Alpha versions of some builds)
if (version=~ "^2\.5\.([0-9]|1[0-8])([^0-9]|$)")
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report,severity:SECURITY_HOLE, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
