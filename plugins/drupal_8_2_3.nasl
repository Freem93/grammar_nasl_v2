#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95026);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/13 17:57:45 $");

  script_cve_id(
    "CVE-2016-9449",
    "CVE-2016-9450",
    "CVE-2016-9451",
    "CVE-2016-9452"
  );
  script_bugtraq_id(94367);
  script_osvdb_id(
    147439,
    147440,
    147441,
    147442
  );

  script_name(english:"Drupal 7.x < 7.52 / 8.x < 8.2.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 7.x prior to
7.52 or 8.x prior to 8.2.3. It is, therefore, affected by the multiple
vulnerabilities :

  - An information disclosure vulnerability exists in the
    taxonomy module when using access query tags that are
    inconsistent with the standard system used by Drupal
    Core. An unauthenticated, remote attacker can exploit
    this to disclose sensitive information regarding
    taxonomy terms. (CVE-2016-9449)

  - A flaw exists in the password reset form due to a
    failure to properly specify a cache context. An
    unauthenticated, remote attacker can exploit this to
    poison the cache, by adding, for example, unwanted
    content to the page. Note that this issue only
    affects version 8.x. (CVE-2016-9450)

  - A cross-site redirection vulnerability exists in the
    confirmation form due to improper validation of input
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted link,
    to redirect the user to a website of the attacker's
    choosing. Note that this issue only affects version
    7.x. (CVE-2016-9451)

  - A denial of service vulnerability exists in the
    transliterate mechanism when handling specially crafted
    URLs. An unauthenticated, remote attacker can exploit
    this to cause a crash. Note that this issue only affects
    version 8.x. (CVE-2016-9452)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2016-005");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.52");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.2.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.52 / 8.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  {"min_version" : "7.0", "fixed_version" : "7.52"},
  {"min_version" : "8.0", "fixed_version" : "8.2.3"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
