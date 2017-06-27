#TRUSTED 0f231543099e674e48273bcc9a46d795349649d130b4d900dc2595f32dd44a8eec18f07bba428655b69ab15dc0cf5491be35e6a8529a76b676e558aab1f038106922e3d57e1222c0277b8471fab29e9e60049197e259e242038076516639f1fbded04469e1525d0f0cd747eea60a761ffd2d287496e449d965d56704d9a639ee37a694215cb3504039ca9c724338ab01e8f7e05a2d9e92c2bf7e18c7d4151e3855a5fb8a9d5111415adcf7b8463d9f684de88b379e4b499b07d8d2c6dd9a625ca63f7b59657d5966978bdbbb4a8d8d4f77e4289996bcb5b97102206a2404751070db211c5bcdf8c38730cff8e10f1cf8f931e389e09701562a71d3b2ca300154df18f169f22a5792d404514099969aa27abe470cd2d8889c1645c192200f5e8bb49477e96fa5d0e0eaeefac63c56a2409e6c5d44f64800c6e53b16698f2158373a4eaf38ece5f677a15060bc57857c320bc248aba716d7fcc27225704ee58df6d3f4739e896954c9f1aace56d3f6020523a48724c7305d86d67b4122a0a14e6be071c16217940a930ca211cfcffb73fa34c0e3be2b14912d7fa3451511f42b1f0cbf680700cb25fd64da69a8372d3adfb2d52a288a17bbe294856f13f731516577759503f99d47661def6839d053cff75d71533c5962674447c385e4ae9307b08ca6beba6ef0d1627c6ad3efd3f61ea2a3ef9e8efeeb67ea885bd37d3c037134
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78067);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/17");

  script_cve_id("CVE-2014-6277", "CVE-2014-6278");
  script_bugtraq_id(70165, 70166);
  script_osvdb_id(112158, 112169);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34860");

  script_name(english:"Bash Remote Code Execution (CVE-2014-6277 / CVE-2014-6278) (Shellshock)");
  script_summary(english:"Logs in with SSH.");

  script_set_attribute(attribute:"synopsis", value:"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker could remotely execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Oct/9");
  # http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40f2f5a");
  script_set_attribute(attribute:"solution", value:"Update Bash.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("dump.inc");
include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");


function report_and_exit(port, command, output, patch_check)
{
  local_var hdr, report;

  report = NULL;
  if (report_verbosity > 0)
  {
    hdr =
    '\n' + 'Nessus was able to login via SSH and run the following command :' +
    '\n' +
    '\n' + command;

    report =
      hdr  +
      '\n' +
      '\n' + 'and read the output :' +
      '\n' +
      '\n' + output +
      '\n';

    if(patch_check)
    {
      report +=
        'This indicates that the patch for CVE-2014-6277 and ' +
        '\n' + 'CVE-2014-6278 is not installed.';
    }

  }
  security_hole(port:port, extra:report);
  exit(0);
}


if ( islocalhost() )
{
 info_t = INFO_LOCAL;
}
else
{
 ret = ssh_open_connection();
 if ( !ret ) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
 info_t = INFO_SSH;
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

ret = ssh_open_connection();
if ( !ret ) audit(AUDIT_FN_FAIL, 'ssh_open_connection');

# Check CVE-2014-6277
#
# - We check CVE-2014-6277 first because this CVE covers some older
#   bash versions while CVE-2014-6278 doesn't, according to
#   http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html.
#
# - The CVE-2014-6277 PoC produces a segfault.

command = 'E="() { x() { _; }; x() { _; } <<A; }"' + ' bash -c E';
output = ssh_cmd(cmd:command, noexec:TRUE);

if( "egmentation fault" >< output
 || "egmentation Fault" >< output) # Solaris
{
  report_and_exit(port:port, command: command, output: output);
}

# Problem reported on AIX 6.1 TL 8 SP 1 with bash 4.3.7 (redmine 10989)
# Disable CVE-2014-6278 check for now

# CVE-2014-6277 detection fails, try to detect CVE-2014-6278,
# This CVE appears to work against bash 4.2 and 4.3.,
# but not against 4.1 or below.
#
#test_command = "echo Plugin output: $((1+1))";
#command = "E='() { _; } >_[$($())] { " + test_command + "; }' bash -c E";
#output = ssh_cmd(cmd:command);

#if ("Plugin output: 2" >< output) vuln_6278 = TRUE;

# ok we detected CVE-2014-6278, send another command
# hoping to get a more convincing output
#if(vuln_6278)
#{
#  test_command = "/usr/bin/id";
#  command2 = "E='() { _; } >_[$($())] { " + test_command + "; }' bash -c E";
#  output2 = ssh_cmd(cmd:command2);
#  if (output2 =~ "uid=[0-9]+.*gid=[0-9]+.*")
#  {
#    command = command2;
#    output  = output2;
#  }
#  report_and_exit(port:port, command:command, output:output);
#}

# If we still cannot detect CVE-2014-6277 or CVE-2014-6278,
# we try to determine if the patch for these CVEs has been applied.
command = "E='() { echo not patched; }' bash -c E";
output = ssh_cmd(cmd:command);


# Patch not installed
# Ignore cases where the host returns an "unknown command" error and returns the entire command
if (("not patched" >< output) && ("echo not patched" >!< output))
  report_and_exit(port:port, command:command, output:output, patch_check:TRUE);
# Patch installed
else audit(AUDIT_HOST_NOT, "affected.");


