#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88982);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2015-5970");
  script_bugtraq_id(83238);
  script_osvdb_id(134429);
  script_xref(name:"ZDI", value:"ZDI-16-167");

  script_name(english:"Novell ZENworks ChangePassword RPC XPath Injection");
  script_summary(english:"Sends ChangePassword requests to exercise XPath injection.");

  script_set_attribute(attribute:"synopsis", value:
"The remote ZENworks server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Novell ZENWworks Configuration Management (ZCM) server is
affected by an information disclosure vulnerability in the
ChangePassword RPC implementation that is triggered when handling
malformed queries involving a system entity reference. An
unauthenticated, remote attacker can exploit this, via XPath
injection, to read arbitrary text files.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-167/");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7017240");
  script_set_attribute(attribute:"solution", value:
"Apply the patch provided by Micro Focus.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_control_center_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/zenworks_control_center");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

appname = "Novell ZENworks Control Center";
port = get_http_port(default:443);
install = get_install_from_kb(
  appname:"zenworks_control_center",
  port:port,
  exit_on_fail:TRUE);

##
# POSTs a message to the ChangePassword URL and examines the response
# provided by the server. Unexpected responses will result in an audit.
# @data the HTTP payload
# @expected_status the expected status description embedded in the returned XML
# @expected_number the expected HTTP status embedded in the returned XML
##
function query_zenworks(data, expected_status, expected_number)
{
  local_var res = http_send_recv3(
    method:"POST",
    item:"/CasaAuthTokenSvc/Rpc?method=ChangePassword",
    port:port,
    data:data,
    content_type:"text/xml",
    exit_on_fail:TRUE);

  if (isnull(res[0]) || isnull(res[2])) audit(AUDIT_RESP_BAD, port);
  if (res[0] != 'HTTP/1.1 200 OK\r\n') audit(AUDIT_INST_VER_NOT_VULN, appname);
  local_var match = eregmatch(
    pattern:"<status><description>([a-zA-Z ]+)</description>([1-9]00)</status>",
    string: res[2]);

  if (isnull(match) ||
      match[1] != expected_status ||
      match[2] != expected_number) audit(AUDIT_INST_VER_NOT_VULN, appname);
}

# check to see if XPath injection is possible.
data = 
  '<?xml version="1.0" encoding="UTF-8"?>\n'+
  '<change_password_req>\n' +
    '<realm>\'nessus</realm>\n' +
    '<username>Nessus</username>\n' +
    '<old_token>dGVzdA==</old_token>\n' +
    '<new_token>dGVzdA==</new_token>\n' +
  '</change_password_req>';

query_zenworks(data:data, expected_status:"Internal Server Error", expected_number:"500");


# If we got here than the above broke the XPath query in
# some way. The following will determine if Zenworks has
# the patch the detects XPath injection
data = 
  '<?xml version="1.0" encoding="UTF-8"?>\n'+
  '<change_password_req>\n' +
    '<realm>nessus()=[]:,*/</realm>\n' +
    '<username>Nessus</username>\n' +
    '<old_token>dGVzdA==</old_token>\n' +
    '<new_token>dGVzdA==</new_token>\n' +
  '</change_password_req>';

query_zenworks(data:data, expected_status:"OK", expected_number:"200");

report = '\nNessus was able to use characters associated with XPath injection' +
  '\nin a ChangePassword request.';
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
