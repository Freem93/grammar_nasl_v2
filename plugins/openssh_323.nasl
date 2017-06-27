#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44072);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/07/06 14:12:41 $");

  script_cve_id("CVE-2002-0765");
  script_bugtraq_id(4803);
  script_osvdb_id(5113);

  script_name(english:"OpenSSH < 3.2.3 YP Netgroups Authentication Bypass");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SSH server has an authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is older than 3.2.3.  It therefore may be affected by an
authentication bypass issue.  On systems using YP with netgroups, sshd
authenticates users via ACL by checking for the requested username and
password.  Under certain conditions when doing ACL checks, it may
instead use the password entry of a different user for authentication. 
This means unauthorized users could authenticate successfully, and
authorized users could be locked out."
  );
  script_set_attribute(attribute:"see_also",value:"http://monkey.org/openbsd/archive/bugs/0205/msg00141.html");
  script_set_attribute(attribute:"see_also",value:"http://www.openssh.org/txt/release-3.2.3");
  script_set_attribute(attribute:"see_also",value:"http://www.openbsd.org/errata31.html#sshbsdauth");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 3.2.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

match = eregmatch(string:version, pattern:'^([0-9.]+)');
if (isnull(match)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
  exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

ver = split(match[1], sep:'.', keep:FALSE);
fix = '3.2.3';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
