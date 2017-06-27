#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77983);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2014-3548", "CVE-2014-3551");
  script_bugtraq_id(68763, 68766);
  script_osvdb_id(109342, 109345);

  script_name(english:"Moodle Multiple XSS");
  script_summary(english:"Checks for patched .js files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by multiple
cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle installed on the remote host is affected by
multiple cross-site scripting vulnerabilities due to the application
failing to properly sanitize user-supplied input to multiple
parameters. An attacker can leverage these vulnerabilities to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site.

Note that Nessus has not tested for each issue, but has checked for
patched JavaScript files to verify a patched version is running.");
  script_set_attribute(attribute:"see_also", value:"https://moodle.org/mod/forum/discuss.php?d=264270");
  script_set_attribute(attribute:"see_also", value:"https://moodle.org/mod/forum/discuss.php?d=264273");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.4.11 / 2.5.7 / 2.6.4 / 2.7.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

patched = 0;
file_count = 0;
report_url = '';

file1 = "/lib/yui/build/moodle-core-notification-exception/moodle-core-notification-exception-debug.js"; # Versions 2.6.x-2.7.x
file2 = "/lib/yui/notification/notification.js"; # Versions 2.4.x
file3 = "/grade/grading/form/rubric/js/rubriceditor.js"; # Versions 2.4.x-2.7.x
file4 = "/lib/yui/src/notification/meta/notification.json"; # 2.5.x - 2.7.x
files = make_list(file1, file2, file3, file4);

file_pats = make_array();
file_pats[file1] = "Y\.Escape\.html\(config\.name\)";
file_pats[file2] = "Y\.Escape\.html\(config\.name\)";
file_pats[file3] = "\.set\('innerHTML', Y\.Escape\.html\(value\)";
file_pats[file4] = '"escape"';

foreach file (files)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + file,
    exit_on_fail : TRUE
  );

  if (res[0] =~ "404") continue;

  file_count++;
  if (ereg(pattern:file_pats[file], string:res[2], multiline:TRUE)) patched++;
  else report_url += install_url + file + '\n  ';
}

if (patched == file_count) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  if (file_count > 1) url = 'URLs';
  else url = 'URL';

  report =
    '\n' + 'Nessus was able to verify the issue by examining the page source from' +
    '\n' + 'the following ' + url + ' : ' +
    '\n' +
    '\n' + '  ' + report_url;
  security_warning(port:port, extra:report);
}
else security_warning(port);
