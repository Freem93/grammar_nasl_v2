#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44065);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/01/28 17:35:14 $");

  script_cve_id("CVE-2008-5161");
  script_bugtraq_id(32319);
  script_osvdb_id(50036);
  script_xref(name:"CERT", value:"958563");

  script_name(english:"OpenSSH < 5.2 CBC Plaintext Disclosure");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH service running on the remote host has an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of OpenSSH running on the remote host has an information
disclosure vulnerability.  A design flaw in the SSH specification
could allow a man-in-the-middle attacker to recover up to 32 bits of
plaintext from an SSH-protected connection in the standard
configuration.  An attacker could exploit this to gain access to
sensitive information."
  );
  # http://web.archive.org/web/20090523091544/http://www.cpni.gov.uk/docs/vulnerability_advisory_ssh.txt
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?4984aeb9");
  script_set_attribute(attribute:"see_also",value:"http://www.openssh.com/txt/cbc.adv");
  script_set_attribute(attribute:"see_also",value:"http://www.openssh.com/txt/release-5.2");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 5.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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

match = eregmatch(string:version, pattern:'^([0-9.]+)');
if (isnull(match)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
  exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

ver = split(match[1], sep:'.', keep:FALSE);
for (i = 0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 5 ||
  (ver[0] == 5 && ver[1] < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");

