#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57337);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-4634");
  script_bugtraq_id(51099);
  script_osvdb_id(78030);

  script_name(english:"phpMyAdmin 3.4.x < 3.4.8 XSS (PMASA-2011-18)");
  script_summary(english:"Checks for patch in phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin hosted on the remote server is 3.4.x prior
to 3.4.8 and is affected by a cross-site scripting vulnerability.  The
database name is not properly sanitized in the file
'js/db_operations.js' when attempting to rename a database.

Note that this version is reportedly affected by several other cross-
site scripting vulnerabilities.  However, Nessus has not tested for
these vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-18.php");
  script_set_attribute(attribute:"solution", value:
"Either apply the vendor patches or upgrade to phpMyAdmin version
3.4.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port    = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir     = install['dir'];
request_url = '/js/db_operations.js';

res = http_send_recv3(
  port   : port,
  method : "GET",
  item   : dir + request_url,
  exit_on_fail : TRUE
);

# Affects 3.4.x < 3.4.8
if (
  'var d="CREATE DATABASE "+$("#new_db_name").val()+" / DROP DATABASE' >< res[2] &&
  'var d=escapeHtml("CREATE DATABASE "+$("#new_db_name").val()+" / DROP DATABASE' >!< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:dir + request_url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The phpMyAdmin install at "+build_url(port:port,qs:dir)+" is not affected.");
