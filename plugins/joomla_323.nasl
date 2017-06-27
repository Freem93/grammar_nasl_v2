#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73025);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id(
    "CVE-2014-7981",
    "CVE-2014-7982",
    "CVE-2014-7983",
    "CVE-2014-7984"
  );
  script_bugtraq_id(
    77808,
    80037,
    80051,
    80065
  );
  script_osvdb_id(
    103126,
    103958,
    104119,
    104120,
    104122
  );
  script_xref(name:"EDB-ID", value:"31459");

  script_name(english:"Joomla! 3.x < 3.2.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 3.x prior to 3.2.3.
It is, therefore, affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists within
    weblinks-categories due to improper sanitization of
    user-supplied input to the category 'ID' parameter
    before using it in SQL queries. An unauthenticated,
    remote attacker can exploit this to inject or manipulate
    SQL queries against the back-end database, resulting in
    the manipulation or disclosure of arbitrary data.
    (CVE-2014-7981)

  - An unspecified cross-site scripting (XSS) vulnerability
    exists due to improper validation of input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2014-7982)

  - A cross-site scripting (XSS) vulnerability exists within
    the index.php/single-contact script due to improper
    validation of input to the 'jform[contact_email]' POST
    parameter before returning it to users. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2014-7983)

  - A security bypass vulnerability exists that allows a
    remote attacker to bypass intended restrictions and log
    into the system using GMail credentials. (CVE-2014-7984)

  - A SQL injection vulnerability exists in the
    ModTagssimilarHelper::getList() function within file
    modules/mod_tags_similar/helper.php due to improper
    sanitization of user-supplied input before using it in
    SQL queries. An unauthenticated, remote attacker can
    exploit this to inject or manipulate SQL queries against
    the back-end database, resulting in the manipulation or
    disclosure of arbitrary data. (VulnDB 103126)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5538-joomla-3-2-3-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?559a3e03");
  # https://developer.joomla.org/security/578-20140301-core-sql-injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?356cb20e");
  # https://developer.joomla.org/security/579-20140302-core-xss-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5e7e44a");
  # https://developer.joomla.org/security/580-20140303-core-xss-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47f311a4");
  # https://developer.joomla.org/security/581-20140304-core-unauthorised-logins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9bf48e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Joomla 3.2.2 mod_tags_similar SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
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

fix = "3.2.3";

# Branch Check
if (!(version =~ "^3\.")) exit(0,'The version of Joomla installed at '+install_loc+' is not 3.x.');

if (version == "3.2")
  audit(AUDIT_VER_NOT_GRANULAR, app, version);

# Versions 3.x < 3.2.3 are vulnerable (There are alpha builds of some versions)
if (
  version =~ "^3\.[01]([^0-9]|$)" ||
  version =~ "^3\.2\.[0-2]([^0-9]|$)"
)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(
    port     : port,
    extra    : report,
    severity : SECURITY_HOLE,
    xss      : TRUE,
    sqli     : TRUE
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
