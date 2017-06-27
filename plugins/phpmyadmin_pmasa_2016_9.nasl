#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88987);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_cve_id("CVE-2016-2044", "CVE-2016-2045");
  script_bugtraq_id(82100, 82104);
  script_osvdb_id(133792, 133793);

  script_name(english:"phpMyAdmin 4.5.x < 4.5.4 Multiple Vulnerabilities (PMASA-2016-8, PMASA-2016-9)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.5.x prior to 4.5.4.
It is, therefore, affected by the following vulnerabilities :

  - An information disclosure vulnerability exists in
    multiple scripts that allows a remote attacker, via a
    specially crafted request, to disclose the software's
    installation path. (CVE-2016-2044)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the SQL
    editor. An authenticated, remote attacker can exploit
    this, via a specially crafted SQL query, to execute
    arbitrary script code in a user's browser session.
    (CVE-2016-2045)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-8/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-9/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.5.4 or later. Alternatively, apply the
patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "phpMyAdmin";
get_install_count(app_name:app, exit_if_zero:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [{"min_version" : "4.5", "fixed_version" : "4.5.4"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
