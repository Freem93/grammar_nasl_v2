#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70918);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_bugtraq_id(63598);
  script_osvdb_id(
    99524,
    99525,
    99526,
    99527,
    99528
  );

  script_name(english:"Joomla! 2.5.x < 2.5.16 / 3.x < 3.1.6 Multiple XSS");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 2.5.x prior to 2.5.16
or 3.x prior to 3.1.6. It is, therefore, affected by multiple
cross-site (XSS) scripting vulnerabilities, related to the
com_contact, com_weblinks, and com_newsfeeds components, due to
improper validation of input before returning it to users. An
unauthenticated, remote attacker can exploit these, via a specially
crafted request, to execute arbitrary script code in a user's browser
session.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security/570-core-xss-20131101.html");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security/571-core-xss-20131102.html");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security/572-core-xss-20131103.html");
  # 2.5.16 announce
  # https://www.joomla.org/announcements/release-news/5518-joomla-2-5-16-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f6d238");
  # 3.2.0 announce (also includes 3.1.6 announce)
  # https://www.joomla.org/announcements/release-news/5516-joomla-3-2-0-stable-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b771e1b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version Joomla! version 2.5.16 / 3.1.6 / 3.2.0 or later.
Alternatively, apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

fix = "2.5.16 / 3.1.6 / 3.2.0";

# Check granularity
# All 3.0.x are vuln
if (version =~ "^2(\.5)?$" || version =~ "^3(\.[12])?$") audit(AUDIT_VER_NOT_GRANULAR, "app", port, version);

# Check branch
if (version !~ "^2\.5\." && version !~ "^3\.(0($|\.)|[12]\.)") exit(0, "The Joomla! "+version+" install at "+install_loc+" is not 2.5.x / 3.0.x / 3.1.x / 3.2.x.");

# Versions 2.5.x < 2.5.16 and 3.x < 3.1.6 are vulnerable
# Also note: 3.2.0.alpha appears vuln (by date); beta seems not to exist
if (
  version =~ "^2\.5\.([0-9]|1[0-5])($|[^0-9])"
  ||
  version =~ "^3\.0($|[^0-9])"
  ||
  version =~ "^3\.1\.[0-5]($|[^0-9])"
  ||
  version == "3.2.0.alpha"
)
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
