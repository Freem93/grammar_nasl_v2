#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86655);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id(
    "CVE-2015-7297",
    "CVE-2015-7857",
    "CVE-2015-7858",
    "CVE-2015-7859",
    "CVE-2015-7899"
  );
  script_bugtraq_id(
    77295,
    77296,
    77297
  );
  script_osvdb_id(
    129338,
    129339,
    129340,
    129341,
    129342
  );
  script_xref(name:"EDB-ID", value:"38797");

  script_name(english:"Joomla! 3.x < 3.4.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 3.x prior to 3.4.5.
It is, therefore, affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists in
    com_contenthistory due to improper sanitization of input
    to the 'list[select]' parameter. An unauthenticated,
    remote attacker can exploit this to disclose or
    manipulate arbitrary data on the back-end database.
    (CVE-2015-7297)

  - A SQL injection vulnerability exists in the history.php
    script due to improper sanitization of input to the
    'list[select]' parameter. An unauthenticated, remote
    attacker can exploit this to disclose or manipulate
    arbitrary data on the back-end database. (CVE-2015-7857)

  - A SQL injection vulnerability exists exists due to
    improper sanitization of unspecified input. An
    unauthenticated, remote attacker can exploit this to
    disclose or manipulate arbitrary data on the back-end
    database. (CVE-2015-7858)

  - An unspecified flaw exists in com_contenthistory that is
    related to unsafe permissions. An unauthenticated,
    remote attacker can exploit this to disclose sensitive
    information. (CVE-2015-7859)

  - An unspecified flaw exists in com_content that is
    related to unsafe permissions. An unauthenticated,
    remote attacker can exploit this, via a crafted request,
    to disclose sensitive information. (CVE-2015-7899)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5634-joomla-3-4-5-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07146f28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Joomla Core SQLi list[select]");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Joomla Content History SQLi Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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

fix = "3.4.5";

# Check granularity
if (version =~ "^3(\.[0-4])?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Versions  3.x < 3.4.5 are vulnerable
# (There are Alpha versions of some builds)
if (version =~ "^3\.([0-3]|4\.[0-4])($|[^0-9])")
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, sqli:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
