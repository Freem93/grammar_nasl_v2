#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17706);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2009-2904");
  script_bugtraq_id(36552);
  script_osvdb_id(58495);
  script_xref(name:"RHSA", value:"2009:1470");

  script_name(english:"Red Hat Enterprise Linux OpenSSH ChrootDirectory Local Privilege Escalation");
  script_summary(english:"Checks OpenSSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host has a privilege escalation
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host may have a privilege escalation vulnerability.  OpenSSH on Red
Hat Enterprise Linux 5, Fedora 11, and possibly other platforms use an
insecure implementation of the 'ChrootDirectory' configuration
setting, which could allow privilege escalation.  Upstream OpenSSH is
not affected. 

The fix for this issue does not change the version in the OpenSSH
banner, so this may be a false positive."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=522141");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate patch listed in Red Hat security advisory
RHSA-2009:1470-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Only RHEL and FC packages are affected
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);
bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

match = eregmatch(string:version, pattern:'^([0-9.]+)');
if (isnull(match)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
  exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

ver = match[1];

if (ver == '4.3')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The OpenSSH version "+version+" server listening on port "+port+" is not affected.");
