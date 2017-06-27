#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99690);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/27 15:16:32 $");

  script_cve_id("CVE-2017-6919");
  script_bugtraq_id(97941);
  script_osvdb_id(156027);
  script_xref(name:"IAVA", value:"2017-A-0124");

  script_name(english:"Drupal 8.x < 8.2.8 / 8.3.x < 8.3.1 Access Bypass Vulnerability (SA-CORE-2017-002)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by an
access bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 8.x prior to 8.2.8 or 8.3.x prior to
8.3.1. It is, therefore, affected by an access bypass vulnerability
due to an unspecified flaw when the RESTful Web Services (rest) module
is enabled and the site allows PATCH requests. An authenticated,
remote attacker can exploit this to bypass critical access
restrictions.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2017-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.2.8");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.3.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.2.8 / 8.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:"Drupal", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "8.0", "max_version" : "8.0.4", "fixed_version" : "8.0.5" },
  { "min_version" : "8.1", "max_version" : "8.1.10", "fixed_version" : "8.1.11" },
  { "min_version" : "8.2", "max_version" : "8.2.7", "fixed_version" : "8.2.8" },
  { "min_version" : "8.3", "max_version" : "8.3.0", "fixed_version" : "8.3.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
