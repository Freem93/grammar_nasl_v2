#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85690);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/22 18:55:31 $");

  script_osvdb_id(126641);

  script_name(english:"OpenSSH 7.x < 7.1 PermitRootLogin Security Bypass");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is 7.x prior to 7.1. It is, therefore, affected by a security
bypass vulnerability due to a logic error that is triggered under
certain compile-time configurations when PermitRootLogin is set to
'prohibit-password' or 'without-password'. An unauthenticated, remote
attacker can exploit this to permit password authentication to root
while preventing other forms of authentication.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) audit(AUDIT_NOT_LISTEN, "OpenSSH", port);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (backported) audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

# Affected : 7.x < 7.1
if (version =~ "^7\.0($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.1\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
