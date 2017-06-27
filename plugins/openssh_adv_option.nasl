#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10771);
  script_version ("$Revision: 1.28 $");
  script_cvs_date("$Date: 2012/12/10 03:02:35 $");

  script_cve_id("CVE-2001-0816", "CVE-2001-1380");
  script_bugtraq_id(3345, 3369);
  script_osvdb_id(5536, 642);
  script_xref(name:"CERT", value:"905795");

  script_name(english:"OpenSSH 2.5.x - 2.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote version of OpenSSH contains multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running
OpenSSH version between 2.5.x and 2.9.  Such versions reportedly
contain multiple vulnerabilities :

  - sftp-server does not respect the 'command=' argument of
    keys in the authorized_keys2 file. (CVE-2001-0816)

  - sshd does not properly handle the 'from=' argument of 
    keys in the authorized_keys2 file. If a key of one type 
    (e.g. RSA) is followed by a key of another type (e.g. 
    DSA) then the options for the latter will be applied to
    the former, including 'from=' restrictions. This problem
    allows users to circumvent the system policy and login
    from disallowed source IP addresses. (CVE-2001-1380)");

  script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/advisories/ssh_option.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bb81c0a");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.9.9");

  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 2.9.9" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2001-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ssh", exit_on_fail:TRUE);

banner = get_kb_item_or_exit("SSH/banner/"+port);
bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

# Pull out numeric portion of version.
matches = eregmatch(string:version, pattern:'^([0-9.]+)');
if (isnull(matches)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
  exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

if (
  ver_compare(ver:matches[1], fix:"2.5", strict:FALSE) < 0 ||
  ver_compare(ver:matches[1], fix:"2.9.9", strict:FALSE) >= 0
) exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 2.9.9' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
