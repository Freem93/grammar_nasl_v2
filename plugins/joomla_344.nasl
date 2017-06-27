#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86020);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2015-6939");
  script_bugtraq_id(76750);
  script_osvdb_id(127453);

  script_name(english:"Joomla! 3.4.x < 3.4.4 Login Module XSS");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 3.4.x prior to 3.4.4.
It is, therefore, affected a cross-site (XSS) scripting vulnerability
in the login module due to improper validation of user-supplied input.
An unauthenticated, remote attacker can exploit this to execute
arbitrary script code in a user's browser session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5628-joomla-3-4-4-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c020854");
  # https://developer.joomla.org/security-centre/626-20150908-core-xss-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b2f149a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

fix = "3.4.4";

# Check granularity
if (version =~ "^3(\.[0-4])?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Versions  3.4.x < 3.4.4 are vulnerable
# (There are Alpha versions of some builds)
if (version =~ "^3\.4\.[0-3]([^0-9]|$)")
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
