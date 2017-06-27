#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44080);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2008-3259");
  script_bugtraq_id(30339);
  script_osvdb_id(47227);

  script_name(english:"OpenSSH X11UseLocalhost X11 Forwarding Port Hijacking");
  script_summary(english:"Checks OpenSSH server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service may be affected by an X11 forwarding port
hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of SSH installed on the remote
host is older than 5.1 and may allow a local user to hijack the X11
forwarding port.  The application improperly sets the 'SO_REUSEADDR'
socket option when the 'X11UseLocalhost' configuration option is
disabled.

Note that most operating systems, when attempting to bind to a port
that has previously been bound with the 'SO_REUSEADDR' option, will
check that either the effective user-id matches the previous bind
(common BSD-derived systems) or that the bind addresses do not overlap
(Linux and Solaris).  This is not the case with other operating
systems such as HP-UX.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/release-5.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH version 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

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

ver = match[1];
fix = '5.1';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
