#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44075);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2005-2666", "CVE-2007-4654", "CVE-2004-2760");
  script_osvdb_id(39165, 45873, 49386);

  script_name(english:"OpenSSH < 4.0 known_hosts Plaintext Host Information Disclosure");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by an information disclosure
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH prior to 4.0.  Versions of OpenSSH earlier than 4.0 are
affected by an information disclosure vulnerability because the
application stores hostnames, IP addresses, and keys in plaintext in
the 'known_hosts' file.  A local attacker, exploiting this flaw, could
gain access to sensitive information that could be used in subsequent
attacks.");

  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/release-4.0");
  script_set_attribute(attribute:"see_also", value:"http://nms.csail.mit.edu/projects/ssh/");
  script_set_attribute(attribute:"see_also", value:"http://www.eweek.com/c/a/Security/Researchers-Reveal-Holes-in-Grid/");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_cwe_id(16, 255, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit('SSH/banner/'+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ('openssh' >!< bp_banner) exit(0, 'The SSH service on port '+port+' is not OpenSSH.');
if (backported) exit(1, 'The banner from the OpenSSH server on port '+port+' indicates patches may have been backported.');

# Check the version in the banner.
matches = eregmatch(string:bp_banner, pattern:'openssh[-_]([0-9][-._0-9a-z]+)');
if (isnull(matches)) exit(0, 'Could not parse number from version string on port ' + port + '.');

version = matches[1];
if (version =~ '^[0-3]\\.')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 4.0\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, 'The OpenSSH server on port '+port+' is not affected as it\'s version '+version+'.');
