#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99662);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id(
    "CVE-2016-5701",
    "CVE-2016-5703",
    "CVE-2016-5705",
    "CVE-2016-5706",
    "CVE-2016-5730",
    "CVE-2016-5731",
    "CVE-2016-5733",
    "CVE-2016-5734",
    "CVE-2016-5739"
  );
  script_bugtraq_id(
    91381,
    91378,
    91383,
    91376,
    91379,
    91384,
    91390,
    91387,
    91389
  );
  script_osvdb_id(
    140414,
    140504,
    140505,
    140506,
    140507,
    140508,
    140495,
    140496,
    140498,
    140499,
    140500,
    140503,
    140509,
    140510,
    140511,
    140512,
    140513,
    140514,
    140515,
    140516,
    140517
  );

  script_name(english:"phpMyAdmin 4.4.x < 4.4.15.7 Multiple Vulnerabilities (PMASA-2016-17, PMASA-2016-19, PMASA-2016-21 - PMASA-2016-24, PMASA-2016-26 - PMASA-2016-28)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.4.x prior to 
4.4.15.7. It is, therefore, affected by the following vulnerabilities:

  - A flaw exists in the setup/frames/index.inc.php script
    that allows an unauthenticated, remote attacker to access
    the program on a non-HTTPS connection and thereby inject
    arbitrary BBCode against HTTP sessions. (CVE-2016-5701)

  - A flaw exists in the libraries/central_columns.lib.php
    script when handling database names due to improper
    sanitization of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a crafted database
    name, to inject or manipulate SQL queries in the
    back-end database, resulting in modification or
    disclosure of arbitrary data. (CVE-2016-5703)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input
    before returning it to users. An unauthenticated, remote
    attacker can exploit these, via specially crafted
    requests, to execute arbitrary script code or HTML in a
    a user's browser session. (CVE-2016-5705)

  - A flaw exists in the js/get_scripts.js.php script when
    handling a large array in the 'scripts' parameter during
    the loading of a crafted JavaScript file. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-5706)

  - A information disclosure vulnerability exists in the
    Example OpenID Authentication and Setup scripts that
    allows an remote attacker, via multiple vectors, to
    disclose the application's installation path in an
    error message. (CVE-2016-5730)

  - A reflected cross-site scripting (XSS) vulnerability
    exists in the examples/openid.php script when handling
    OpenID error messages due to improper validation of
    input before returning it to users. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2016-5731)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input
    before returning it to users. An unauthenticated, remote
    attacker can exploit these, via specially crafted
    requests, to execute arbitrary script code or HTML in a
    user's browser session. (CVE-2016-5733)

  - A flaw exists in the table search and replace feature
    due to improper sanitization of parameters before
    passing them to the preg_replace() function. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted string, to execute arbitrary PHP
    code. (CVE-2016-5734)

  - An information disclosure vulnerability exists in the
    libraries/Header.class.php script when handling
    transformations due to a failure to use the 'no-referer'
    Content Security Policy (CSP) protection mechanism. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted Transformation, to disclose sensitive
    authentication token information, which then can be
    potentially used to facilitate cross-site request
    forgery (XSRF) attacks. (CVE-2016-5739)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-17/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-19/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-21/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-22/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-23/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-24/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-26/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-27/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-28/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.4.15.7 or later. Alternatively,
apply the patches referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

constraints = [
  { "min_version" : "4.4.0", "max_version" : "4.4.15.6", "fixed_version" : "4.4.15.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:true,sqli:true});
