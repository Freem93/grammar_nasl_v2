#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17702);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/11/22 01:19:34 $");

  script_cve_id("CVE-2002-0746");
  script_osvdb_id(4536, 8002);

  script_name(english:"OpenSSH < 3.6.1p2 Multiple Vulnerabilities");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is ealier than 3.6.1p2.  When compiled for the AIX operating
system with a compiler other than that of the native AIX compiler, an
error exists that can allow dynamic libraries in the current directory
to be loaded before dynamic libraries in the system paths.  This
behavior can allow local users to escalate privileges by creating,
loading and executing their own malicious replacement libraries.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/release-3.6.1p2");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/320038/2003-04-25/2003-05-01/0");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 3.6.1p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

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

match = eregmatch(string:version, pattern:"([0-9.]+)(p([0-9]+))?");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

ver = split(match[1], sep:'.', keep:FALSE);
for (i = 0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 6) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 1) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] == 1 && isnull(match[3])) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] == 1 && !isnull(match[3]) && int(match[3]) < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.6.1p2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The OpenSSH version "+version+" server listening on port "+port+" is not affected.");
