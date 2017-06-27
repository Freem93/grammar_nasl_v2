#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17839);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2000-0999");
  script_osvdb_id(7555);

  script_name(english:"OpenSSH < 2.1.1p3 Format String Privilege Escalation");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OpenSSH server has a format string vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, a version of OpenSSH earlier than 2.1.1p3 is 
running on the remote host.  As such, it is reportedly affected by a 
format string vulnerability."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 2.1.1p3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  # http://lists.mindrot.org/pipermail/openssh-unix-dev/2004-November/022047.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4cd6ac9");
  # http://anoncvs.mindrot.org/index.cgi/openssh/ssh-keygen.c?r1=1.21&r2=1.22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95e39748");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

if (
  version =~ "^[0-1]\." ||
  version =~ "^2\.(0\..+|1\.0([^0-9]|$)|1\.1($|[^0-9p]|p[0-2]([^0-9]|$)))"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.1.1p3' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
