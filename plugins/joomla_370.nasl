#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99691);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_cve_id(
    "CVE-2017-7983",
    "CVE-2017-7984",
    "CVE-2017-7985",
    "CVE-2017-7986",
    "CVE-2017-7987",
    "CVE-2017-7988",
    "CVE-2017-7989",
    "CVE-2017-8057"
  );
  script_bugtraq_id(
    98016,
    98018,
    98020,
    98024,
    98021,
    98022,
    98029,
    98028
  );
  script_osvdb_id(
    156315,
    156316,
    156317,
    156318,
    156319,
    156320,
    156321,
    156322
  );

  script_name(english:"Joomla! < 3.7.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is prior to 3.7.0. It
is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the JMail API due to PHPMail version
    information being included in mail headers. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2017-7983)

  - A cross-site scripting (XSS) vulnerability exists in the
    template manager component due to improper validation of
    input before returning it to users. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-7984)

  - A cross-site scripting (XSS) vulnerability exists in
    unspecified components when handling multibyte
    characters due to improper validation of input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2017-7985)

  - A cross-site scripting (XSS) vulnerability exists in
    unspecified components when handling certain HTML
    attributes due to improper validation of input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2017-7986)

  - A cross-site scripting (XSS) vulnerability exists in the
    template manager component due to inadequate escaping of
    file and folder name input before returning it to users.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session. (CVE-2017-7987)

  - A flaw exists due to improper sanitization of form
    content that allows an unauthenticated, remote attacker
    to overwrite the author of articles. (CVE-2017-7988)

  - A flaw exists in MIME type checking that allows an
    authenticated, remote attacker with low privileges to
    upload SWF files even if this action is not allowed for
    the privilege level. (CVE-2017-7989)

  - Multiple unspecified files exist that allow an
    unauthenticated, remote attacker to disclose the
    software's installation path on systems that have error
    reporting enabled. (CVE-2017-8057)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5703-joomla-3-7-is-here.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a262ee37");
  # https://developer.joomla.org/security-centre/683-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb84a56");
  # https://developer.joomla.org/security-centre/684-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8273195b");
  # https://developer.joomla.org/security-centre/685-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14221e7d");
  # https://developer.joomla.org/security-centre/686-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4788626");
  # https://developer.joomla.org/security-centre/687-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ae9552b");
  # https://developer.joomla.org/security-centre/688-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4582c692");
  # https://developer.joomla.org/security-centre/689-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfc484cb");
  # https://developer.joomla.org/security-centre/690-core-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e30be839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");


port = get_http_port(default:80, php:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"Joomla!", port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "1.5.0", "max_version" : "3.6.5", "fixed_version" : "3.7.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
