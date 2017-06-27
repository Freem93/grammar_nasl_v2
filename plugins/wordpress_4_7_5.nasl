#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100298);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/25 13:56:51 $");

  script_cve_id(
    "CVE-2017-9061",
    "CVE-2017-9062",
    "CVE-2017-9063",
    "CVE-2017-9064",
    "CVE-2017-9065",
    "CVE-2017-9066"
  );
  script_bugtraq_id(98509);
  script_osvdb_id(
    156100,
    157670,
    157672,
    157674,
    157678,
    157679
  );
  script_xref(name:"IAVA", value:"2017-A-0161");

  script_name(english:"WordPress 4.7.x < 4.7.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.7.x prior to 4.7.5.
It is, therefore, affected by multiple vulnerabilities :

  - A DOM-based cross-site scripting (XSS) vulnerability
    exists in the uploadSizeError() function within file
    wp-includes/js/plupload/handlers.js when handling overly
    large file uploads due to improper validation of
    user-supplied input to file names before returning it in
    error messages. An unauthenticated, remote attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2017-9061)

  - A flaw exists in the set_custom_fields() function within
    file wp-includes/class-wp-xmlrpc-server.php when
    accessing post meta data due to improper validation of
    user-supplied input. An authenticated, remote attacker
    can exploit this to gain unauthorized access to meta
    data. (CVE-2017-9062)

  - A stored cross-site scripting (XSS) vulnerability exists
    within file wp-admin/customize.php script due to
    improper validation of user-supplied input to the blog
    name before returning it to users. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-9063)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the request_filesystem_credentials() function within
    file /wp-admin/includes/file.php due to a failure to
    require multiple steps, explicit confirmation, or a
    unique token when performing certain sensitive actions.
    An unauthenticated, remote attacker can exploit this,
    by convincing a user to follow a specially crafted link,
    to disclose the user credentials. (CVE-2017-9064)

  - A flaw exists in the XML-RPC API, specifically within
    file wp-includes/class-wp-xmlrpc-server.php in the
    _insert_post() function, when handling post meta data
    due to a lack of capability checks. An unauthenticated,
    remote attacker can exploit this to manipulate posts
    without having the required capabilities.
    (CVE-2017-9065)

  - An flaw exists in the WP_Http::request() function within
    file wp-includes/class-http.php due to improper
    validation of user-supplied iput. An unauthenticated,
    remote attacker can exploit this to redirect the user to
    a URL of the attacker's choosing. (CVE-2017-9066)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2017/05/wordpress-4-7-5/");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.7.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

# Per https://wordpress.org/download/release-archive/
# only 4.7.x is currently supported :
# "None of these are safe to use, except the latest in the 4.7 series, which is actively maintained."
constraints = [
  { "min_version" : "4.7", "fixed_version" : "4.7.5" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE,xsrf:TRUE}
);
