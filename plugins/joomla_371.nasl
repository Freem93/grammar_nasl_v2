#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100385);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/25 13:56:51 $");

  script_cve_id("CVE-2017-8917");
  script_osvdb_id(157511);
  script_xref(name:"IAVA", value:"2017-A-0159");

  script_name(english:"Joomla! 3.7.x < 3.7.1 fields.php getListQuery() Method SQLi");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 3.7.x prior to 3.7.1.
It is, therefore, affected by a SQL injection vulnerability in the
fields.php script due to improper sanitization of user-supplied input.
An unauthenticated, remote attacker can exploit this to inject or
manipulate SQL queries in the back-end database, resulting in the
disclosure or modification of arbitrary data.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79a94fdc");
  # https://www.joomla.org/announcements/release-news/5705-joomla-3-7-1-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27b1deb5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:"Joomla!", port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "3.7.0", "max_version" : "3.7.0", "fixed_version" : "3.7.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:true});
