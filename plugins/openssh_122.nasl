#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17699);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/17 15:28:25 $");

  script_cve_id("CVE-2000-0143");
  script_osvdb_id(59352, 59353);

  script_name(english:"OpenSSH < 1.2.2 sshd Local TCP Redirection Connection Masking Weakness");
  script_summary(english:"Check OpenSSH banner version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host allows connections to be
redirected."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host allows local users without shell access to redirect TCP
connections with the IDENT 'root@localhost'.  A local attacker could
use this incorrect IDENT to bypass monitoring/logging."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Feb/200");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Feb/212");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Feb/231");
  script_set_attribute(
    attribute:"solution",
    value:
"Either upgrade to OpenSSH 1.2.2 or later or use one of the 'IMMUNE
CONFIGURATIONS' referenced in the advisory titled
'sshd-restricted-users-incorrect-configuration'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

# the only indication of the vulnerable versions:
# "This is presumably a bug in ssh-1.2.27 and OpenSSH 1.2.1 and earlier releases"
# http://seclists.org/bugtraq/2000/Feb/200
if (
  version =~ "^0\." ||
  version =~ "^1\.1\." ||
  version =~ "^1\.2($|[^0-9.]|\.[01]($|[^0-9]))"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.2.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The OpenSSH version "+version+" server listening on port "+port+" is not affected.");
