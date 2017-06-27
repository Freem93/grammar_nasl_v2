#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88021);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/13 13:30:10 $");

  script_cve_id("CVE-2015-6857");
  script_bugtraq_id(77946);
  script_osvdb_id(130684);
  script_xref(name:"HP", value:"HPSBGN03523");
  script_xref(name:"HP", value:"HPSBGN03525");
  script_xref(name:"HP", value:"emr_na-c04900820");
  script_xref(name:"HP", value:"emr_na-c04907374");

  script_name(english:"HP Virtual Table Server (VTS) Database Import RCE");
  script_summary(english:"Checks presence of the VTS Database Import RCE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application running that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP Virtual Table Server running on the remote host is affected 
by a remote code execution vulnerability. An unauthenticated, remote 
attacker can exploit this, via a malicious connection string or SQL 
command, to execute arbitrary code.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04900820
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?917f4e68");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04907374
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23241096");
  # https://packetstormsecurity.com/files/134546/HP-Security-Bulletin-HPSBGN03523-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cf43203");
  # https://softwaresupport.hp.com/group/softwaresupport/search-result/-/facetsearch/document/KM01936061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?363abef6");
  script_set_attribute(attribute:"solution", value:
"Delete the web\admin\adoUtility.js file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:performance_center");
  
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_vts_detect.nasl");
  script_require_keys("installed_sw/HP Virtual Table Server");
  script_require_ports("Services/www", 4000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("url_func.inc");
include("path.inc");
include("json.inc");
include("http.inc");
include("webapp_func.inc");

appname = "HP Virtual Table Server";

# Plugin will exit if VTS is not detected on the host
get_install_count(app_name:appname, exit_if_zero:TRUE);

# Branch off each http port
# Plugin will exit if VTS is not detected on this http port
port = get_http_port(default:4000);
install = get_single_install(
  app_name            : appname,
  port                : port
);

dir = install["path"];
install_url =  build_url(port:port, qs:dir);

# Non-exisiting DB provider, other items are not relevant
conn_str = "Provider=SQLOLEDB_NO_SUCH_PROVIDER;Data Source=" + get_host_ip() +";Initial Catalog=master;Integrated Security=SSPI;";
sql = "select * from sys.syslogins"; 
postdata =  "conn=" + urlencode(str:conn_str) +
            "sql="  + urlencode(str:sql); 

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : "/data/import_database",
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

if(res[0] !~ "^HTTP/[0-9.]+ 200" || !res[2]) 
  audit(AUDIT_RESP_BAD, port);
 
# Get Job Id 
ret = json_read(res[2]);
jobid = ret[0]["jobid"];
if (isnull(jobid))
  exit(1, "Failed to get job id in HTTP response.");

# Get Job status 
#
# 1 = in progress
# 2 = failed
# 3 = succeeded
#
# Final job status is not immediately returned, try a few queries
#
for (i = 0; i < 10; i++)
{
  url = "/data/job_status?jobid=" + jobid + "&_=" + unixtime();
  res = http_send_recv3(
    port            : port,
    method          : "GET",
    item            : url,
    exit_on_fail    : TRUE
  );

  if(res[0] !~ "^HTTP/[0-9.]+ 200" || !res[2]) 
    audit(AUDIT_RESP_BAD, port, "a job status request.");
    
  ret = json_read(res[2]);
  success = ret[0]["success"];
  job     = ret[0]["job"];
  if (!success || isnull(job) || isnull(job["status"]))
    exit(1, "Failed to get job status in HTTP response.");

  status = job["status"];
  msg    = job["msg"];

  if (status == 1)
  {
    sleep(1);
    continue;
  }
  else if (status == 2)
  {
    # adoUtility.js was run to find a DB prodiver, but failed
    if("Provider cannot be found" >< msg)
    {
      security_hole(port:port);
      exit(0);
    }
    # adoUtility.js was deleted as a solution to address the vulnerability
    else if(! msg)
      audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
    # Unexpected error message
    else
      audit(AUDIT_RESP_BAD, port, "a job status request: unexpected error message '"+msg+"'.");
  }
  # Unexpected job status
  else
    audit(AUDIT_RESP_BAD, port, "a job status request: unexpected job status '"+status+"'.");
}
exit(1, "Failed to get a job failure status.");

