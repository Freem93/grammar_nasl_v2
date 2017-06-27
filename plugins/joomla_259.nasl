#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64634);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id(
    "CVE-2013-1453",
    "CVE-2013-1454",
    "CVE-2013-1455"
  );
  script_bugtraq_id(
    57746,
    57751,
    57752
  );
  script_osvdb_id(
    89851,
    89852,
    89858
  );
  script_xref(name:"EDB-ID", value:"24551");

  script_name(english:"Joomla! 2.5.x < 2.5.9 / 3.0.x < 3.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 2.5.x prior to 2.5.9
or 3.0.x prior to 3.0.3. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in the highlight.php script, within the
    PlgSystemHighlight::onAfterDispatch() function, due to
    improper sanitization of input passed via the
    'highlight' parameter before it is used in an
    unserialize() call. An authenticated, remote attacker
    can exploit this issue to unserialize arbitrary PHP
    objects, resulting in disclosure of sensitive
    information, deletion of arbitrary directories, SQL
    injection, or other impacts. (CVE-2013-1453)

  - An unspecified coding error exists that allows an
    unauthenticated, remote attacker to disclose sensitive
    information. (CVE-2013-1454)

  - An unspecified flaw exists when handling undefined
    variables that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2013-1455)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5477-joomla-2-5-9-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7433d5d");
  # https://www.joomla.org/announcements/release-news/5478-joomla-3-0-3-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58ded3b2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 2.5.9 / 3.0.3 or later. Alternatively,
apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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

fix = "2.5.9 / 3.0.3";

# Check granularity
if (version =~ "^2(\.5)?$" || version =~ "^3(\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "app", port, version);

# Versions 2.5.x < 2.5.9 and 3.0.x < 3.0.3 are vulnerable
if (
  version =~ "^2\.5\.[0-8]([^0-9]|$)" ||
  version =~ "^3\.0\.[0-2]([^0-9]|$)"
)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
