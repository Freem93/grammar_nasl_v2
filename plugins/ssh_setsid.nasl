#
# (C) Tenable Network Security, Inc.
#

#
# Note: This is about SSH.com's SSH, not OpenSSH !!
#

include("compat.inc");

if (description)
{
 script_id(11169);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/04/17 17:13:03 $");

 script_cve_id("CVE-2002-1644");
 script_bugtraq_id(6247);
 script_osvdb_id(18240);

 script_name(english:"SSH Secure Shell without PTY setsid() Function Privilege Escalation");
 script_summary(english:"Checks for the remote SSH version");

 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by a privilege escalation
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of SSH Secure Shell running on
the remote host is between 2.0.13 and 3.2.1. There is a bug in such
versions that may allow a non-interactive shell session, such as used
in scripts, to obtain higher privileges due to a flaw in the way
setsid() is used.");
 # http://web.archive.org/web/20021207091314/http://www.ssh.com/company/newsroom/article/286/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7fe1d74");
 script_set_attribute(attribute:"solution", value:"Upgrade to SSH Secure Shell 3.1.5 / 3.2.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

banner = get_kb_item_or_exit("SSH/banner/"+port);
bp_banner = tolower(get_backport_banner(banner:banner));

if (
  !ereg(pattern:"^ssh-[0-9]+\.[0-9]+-[0-9]", string:bp_banner) ||

  "f-secure" >< bp_banner ||
  "tru64 unix" >< bp_banner ||
  "windows" >< bp_banner
) audit(AUDIT_NOT_LISTEN, "SSH Secure Shell", port);

type = get_kb_item("Host/OS/Type");
if (isnull(type) || type != "general-purpose") exit(0, "The host's type is not general-purpose.");

item = eregmatch(pattern:"^ssh-[0-9]\.[0-9]+-([0-9][^ ]+)", string:banner);
if (isnull(item)) exit(1, 'Failed to parse the banner from the SSH server listening on port ' + port + '.');
version = item[1];

if (
  (
    ereg(pattern:"^2\..*$", string:version) &&
    !ereg(pattern:"^2\.0\.([0-9]|0[0-9]|1[0-2])([^0-9]|$)", string:version)
  ) ||
  ereg(pattern:"^3\.(0\..*|1\.[0-4]|2\.[0-1])([^0-9]|$)", string:version)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + banner +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 3.1.5 / 3.2.2' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
