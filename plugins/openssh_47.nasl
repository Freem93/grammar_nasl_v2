#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44078);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2007-4752", "CVE-2007-2243");
  script_bugtraq_id(25628);
  script_osvdb_id(34600, 43371);

  script_name(english:"OpenSSH < 4.7 Trusted X11 Cookie Connection Policy Bypass");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Remote attackers may be able to bypass authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, OpenSSH earlier than 4.7 is running on the
remote host.  Such versions contain an authentication bypass
vulnerability.  In the event that OpenSSH cannot create an untrusted
cookie for X, for example due to the temporary partition being full,
it will use a trusted cookie instead.  This allows attackers to
violate intended policy and gain privileges by causing their X client
to be treated as trusted."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 4.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 287);

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssh.com/txt/release-4.7"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

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

# Pull out numeric portion of version.
matches = eregmatch(string:version, pattern:"^([0-9.]+)");
if (isnull(matches))
  exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

if (ver_compare(ver:matches[0], fix:"4.7", strict:FALSE) >= 0)
  exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.7' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
