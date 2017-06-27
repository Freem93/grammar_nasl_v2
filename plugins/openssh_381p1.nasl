#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44073);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/10/05 10:49:46 $");

  script_cve_id("CVE-2006-0883");
  script_bugtraq_id(16892);
  script_osvdb_id(23797);

  script_name(english:"OpenSSH With OpenPAM DoS");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host has a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is affected by a remote denial of service vulnerability. When
used with OpenPAM, OpenSSH does not properly handle when a forked
child process ends during PAM authentication. This could allow a
remote attacker to cause a denial of service by connecting several
times to the SSH server, waiting for the password prompt and then
disconnecting."
  );
  script_set_attribute(attribute:"see_also",value:"https://bugzilla.mindrot.org/show_bug.cgi?id=839");
  # ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-06:09.openssh.asc
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?170f19e3");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 3.8.1p1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

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

# there was no 3.8.1, so we don't need to worry about checking anything after the 'p'
match = eregmatch(string:version, pattern:'^([0-9.]+)');
if (isnull(match)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
  exit(1, 'Error parsing version: ' + version);

ver = split(match[1], sep:'.', keep:FALSE);
for (i = 0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] < 8) ||
  (ver[0] == 3 && ver[1] == 8 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.8.1p1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
